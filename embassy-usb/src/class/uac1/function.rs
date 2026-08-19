//! What the UAC1 classes share: the audio function's descriptors, the feature unit and sampling
//! frequency control handler, and the feedback endpoint. Only the stream direction differs.

use core::cell::Cell;
use core::future::{Future, poll_fn};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::Poll;

use embassy_sync::blocking_mutex::CriticalSectionMutex;
use embassy_sync::waitqueue::AtomicWaker;
use heapless::Vec;

use super::class_codes::*;
use super::terminal_type::TerminalType;
use super::{Channel, ChannelConfig, FeedbackRefresh, MAX_AUDIO_CHANNEL_COUNT, SampleWidth, Volume};
use crate::control::{self, InResponse, OutResponse, Recipient, Request, RequestType};
use crate::descriptor::{SynchronizationType, UsageType};
use crate::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointInfo, EndpointType};
use crate::types::InterfaceNumber;
use crate::{Builder, Handler, InterfaceAltBuilder};

/// Maximum allowed sampling rate (3 bytes) in Hz.
const MAX_SAMPLE_RATE_HZ: u32 = 0x7FFFFF;

// Volume settings go from -25600 to 0, in steps of 256.
// Therefore, the volume settings are 8q8 values in units of dB.
const VOLUME_STEPS_PER_DB: i16 = 256;
const MIN_VOLUME_DB: i16 = -100;
const MAX_VOLUME_DB: i16 = 0;

/// Maximum number of supported discrete sample rates.
pub(super) const MAX_SAMPLE_RATE_COUNT: usize = 10;

/// Which feature unit controls the host is offered. With neither, no feature unit is described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FeatureUnitControls {
    /// A mute control on the master channel and on each audio channel.
    pub mute: bool,
    /// A volume control on the master channel and on each audio channel.
    pub volume: bool,
}

impl FeatureUnitControls {
    /// Mute and volume.
    pub const ALL: FeatureUnitControls = FeatureUnitControls {
        mute: true,
        volume: true,
    };
    /// No feature unit.
    pub const NONE: FeatureUnitControls = FeatureUnitControls {
        mute: false,
        volume: false,
    };

    /// The bmaControls byte for one channel.
    pub(super) fn bitmap(&self) -> u8 {
        let mut controls = FU_CONTROL_UNDEFINED;
        if self.mute {
            controls |= MUTE_CONTROL;
        }
        if self.volume {
            controls |= VOLUME_CONTROL;
        }
        controls
    }
}

/// Internal state for a USB Audio Class 1.0 class.
pub struct State<'d> {
    control: Option<Control<'d>>,
    shared: SharedControl<'d>,
}

impl<'d> Default for State<'d> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d> State<'d> {
    /// Create a new `State`.
    pub fn new() -> Self {
        Self {
            control: None,
            shared: SharedControl::default(),
        }
    }

    /// Wire the state up — what the host may set, and where — and register
    /// the handler. Returns the monitor a class hands back.
    pub(super) fn register<'b, D: Driver<'d>>(
        &'d mut self,
        builder: &'b mut Builder<'d, D>,
        channels: &'d [Channel],
        sample_rates_hz: &[u32],
        controls: FeatureUnitControls,
        control_interface: InterfaceNumber,
        streaming_endpoint_address: u8,
    ) -> ControlMonitor<'d> {
        self.shared.channels = channels;
        self.shared.sample_rates_hz = Vec::from_slice(sample_rates_hz).expect("at most ten sample rates");
        self.shared
            .sample_rate_hz
            .store(sample_rates_hz.first().copied().unwrap_or(0), Ordering::Relaxed);

        self.control = Some(Control {
            shared: &self.shared,
            streaming_endpoint_address,
            control_interface_number: control_interface,
            controls,
        });

        builder.handler(self.control.as_mut().unwrap());

        ControlMonitor { shared: &self.shared }
    }
}

/// Audio settings for the feature unit.
///
/// Contains volume and mute control.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AudioSettings {
    /// Channel mute states.
    muted: [bool; MAX_AUDIO_CHANNEL_COUNT],
    /// Channel volume levels in 8.8 format (in dB).
    volume_8q8_db: [i16; MAX_AUDIO_CHANNEL_COUNT],
}

impl Default for AudioSettings {
    fn default() -> Self {
        AudioSettings {
            muted: [false; MAX_AUDIO_CHANNEL_COUNT],
            volume_8q8_db: [MAX_VOLUME_DB * VOLUME_STEPS_PER_DB; MAX_AUDIO_CHANNEL_COUNT],
        }
    }
}

struct Control<'d> {
    control_interface_number: InterfaceNumber,
    streaming_endpoint_address: u8,
    controls: FeatureUnitControls,
    shared: &'d SharedControl<'d>,
}

/// Shared data between [`Control`] and the class.
struct SharedControl<'d> {
    /// The collection of audio settings (volumes, mute states).
    audio_settings: CriticalSectionMutex<Cell<AudioSettings>>,

    /// Channel assignments.
    channels: &'d [Channel],

    /// The sample rates the stream offers.
    sample_rates_hz: Vec<u32, MAX_SAMPLE_RATE_COUNT>,

    /// The audio sample rate in Hz.
    sample_rate_hz: AtomicU32,

    // Notification mechanism. An atomic waker, so the monitor can live on a
    // different executor than the handler.
    waker: AtomicWaker,
    changed: AtomicBool,
}

impl<'d> Default for SharedControl<'d> {
    fn default() -> Self {
        SharedControl {
            audio_settings: CriticalSectionMutex::new(Cell::new(AudioSettings::default())),
            channels: &[],
            sample_rates_hz: Vec::new(),
            sample_rate_hz: AtomicU32::new(0),
            waker: AtomicWaker::new(),
            changed: AtomicBool::new(false),
        }
    }
}

impl<'d> SharedControl<'d> {
    fn changed(&self) -> impl Future<Output = ()> + '_ {
        poll_fn(|context| {
            if self.changed.load(Ordering::Relaxed) {
                self.changed.store(false, Ordering::Relaxed);
                Poll::Ready(())
            } else {
                self.waker.register(context.waker());
                Poll::Pending
            }
        })
    }
}

/// Control status change monitor
///
/// Await [`ControlMonitor::changed`] for being notified of configuration changes. Afterwards, the updated
/// configuration settings can be read with [`ControlMonitor::muted`], [`ControlMonitor::volume`] and
/// [`ControlMonitor::sample_rate_hz`].
pub struct ControlMonitor<'d> {
    shared: &'d SharedControl<'d>,
}

impl<'d> ControlMonitor<'d> {
    fn audio_settings(&self) -> AudioSettings {
        self.shared.audio_settings.lock(|x| x.get())
    }

    fn get_logical_channel(&self, search_channel: Channel) -> Option<usize> {
        let index = self.shared.channels.iter().position(|&c| c == search_channel)?;

        // The logical channels start at one (zero is the master channel).
        Some(index + 1)
    }

    /// Whether the host has muted the stream: the master channel, or every
    /// audio channel. A stream that honours it plays or sends silence.
    pub fn muted(&self) -> bool {
        let settings = self.audio_settings();
        let channels = 1..=self.shared.channels.len();
        settings.muted[0] || channels.clone().all(|channel| settings.muted[channel])
    }

    /// Get the volume of a selected channel.
    pub fn volume(&self, channel: Channel) -> Option<Volume> {
        let channel_index = self.get_logical_channel(channel)?;

        if self.audio_settings().muted[channel_index] {
            return Some(Volume::Muted);
        }

        Some(Volume::DeciBel(
            (self.audio_settings().volume_8q8_db[channel_index] as f32) / 256.0f32,
        ))
    }

    /// Get the streaming endpoint's sample rate in Hz.
    pub fn sample_rate_hz(&self) -> u32 {
        self.shared.sample_rate_hz.load(Ordering::Relaxed)
    }

    /// Return a future for when the control settings change.
    pub async fn changed(&self) {
        self.shared.changed().await;
    }
}

impl<'d> Control<'d> {
    fn changed(&mut self) {
        self.shared.changed.store(true, Ordering::Relaxed);
        self.shared.waker.wake();
    }

    /// Whether `channel_index` is the master or one of the stream's channels.
    fn has_channel(&self, channel_index: u8) -> bool {
        channel_index as usize <= self.shared.channels.len()
    }

    fn interface_set_request(&mut self, req: control::Request, data: &[u8]) -> Option<OutResponse> {
        let interface_number = req.index as u8;
        let entity_index = (req.index >> 8) as u8;
        let channel_index = req.value as u8;
        let control_unit = (req.value >> 8) as u8;

        if interface_number != self.control_interface_number.into() {
            debug!("Unhandled interface set request for interface {}", interface_number);
            return None;
        }

        if entity_index != FEATURE_UNIT_ID || !self.has_channel(channel_index) {
            debug!(
                "Unsupported interface set request for entity {} channel {}",
                entity_index, channel_index
            );
            return Some(OutResponse::Rejected);
        }

        if req.request != SET_CUR {
            debug!("Unsupported interface set request type {}", req.request);
            return Some(OutResponse::Rejected);
        }

        let mut audio_settings = self.shared.audio_settings.lock(|x| x.get());
        match control_unit {
            MUTE_CONTROL if self.controls.mute && !data.is_empty() => {
                audio_settings.muted[channel_index as usize] = data[0] != 0;
                debug!("Set channel {} mute state: {}", channel_index, data[0] != 0);
            }
            VOLUME_CONTROL if self.controls.volume && data.len() >= 2 => {
                let volume = i16::from_le_bytes([data[0], data[1]]);
                audio_settings.volume_8q8_db[channel_index as usize] = volume;
                debug!("Set channel {} volume: {}", channel_index, volume);
            }
            _ => return Some(OutResponse::Rejected),
        }

        // Store updated settings
        self.shared.audio_settings.lock(|x| x.set(audio_settings));

        self.changed();

        Some(OutResponse::Accepted)
    }

    fn endpoint_set_request(&mut self, req: control::Request, data: &[u8]) -> Option<OutResponse> {
        let control_selector = (req.value >> 8) as u8;
        let endpoint_address = req.index as u8;

        if endpoint_address != self.streaming_endpoint_address {
            debug!(
                "Unhandled endpoint set request for endpoint {} and control {} with data {:?}",
                endpoint_address, control_selector, data
            );
            return None;
        }

        if control_selector != SAMPLING_FREQ_CONTROL || data.len() < 3 {
            debug!(
                "Unsupported endpoint set request for control selector {}",
                control_selector
            );
            return Some(OutResponse::Rejected);
        }

        let sample_rate_hz: u32 = (data[0] as u32) | (data[1] as u32) << 8 | (data[2] as u32) << 16;
        if !self.shared.sample_rates_hz.contains(&sample_rate_hz) {
            debug!("Unsupported sample rate {} Hz", sample_rate_hz);
            return Some(OutResponse::Rejected);
        }
        self.shared.sample_rate_hz.store(sample_rate_hz, Ordering::Relaxed);

        debug!("Set endpoint {} sample rate to {} Hz", endpoint_address, sample_rate_hz);

        self.changed();

        Some(OutResponse::Accepted)
    }

    fn interface_get_request<'r>(&'r mut self, req: Request, buf: &'r mut [u8]) -> Option<InResponse<'r>> {
        let interface_number = req.index as u8;
        let entity_index = (req.index >> 8) as u8;
        let channel_index = req.value as u8;
        let control_unit = (req.value >> 8) as u8;

        if interface_number != self.control_interface_number.into() {
            debug!("Unhandled interface get request for interface {}.", interface_number);
            return None;
        }

        if entity_index != FEATURE_UNIT_ID || !self.has_channel(channel_index) {
            // Only this function unit can be handled at the moment.
            debug!(
                "Unsupported interface get request for entity {} channel {}.",
                entity_index, channel_index
            );
            return Some(InResponse::Rejected);
        }

        let audio_settings = self.shared.audio_settings.lock(|x| x.get());

        let volume = match (req.request, control_unit) {
            (GET_CUR, MUTE_CONTROL) if self.controls.mute => {
                let mute_state = audio_settings.muted[channel_index as usize];
                buf[0] = mute_state.into();

                debug!("Got channel {} mute state: {}.", channel_index, mute_state);
                return Some(InResponse::Accepted(&buf[..1]));
            }
            (GET_CUR, VOLUME_CONTROL) if self.controls.volume => {
                let volume = audio_settings.volume_8q8_db[channel_index as usize];
                debug!("Got channel {} volume: {}.", channel_index, volume);
                volume
            }
            (GET_MIN, VOLUME_CONTROL) if self.controls.volume => MIN_VOLUME_DB * VOLUME_STEPS_PER_DB,
            (GET_MAX, VOLUME_CONTROL) if self.controls.volume => MAX_VOLUME_DB * VOLUME_STEPS_PER_DB,
            (GET_RES, VOLUME_CONTROL) if self.controls.volume => VOLUME_STEPS_PER_DB,
            _ => return Some(InResponse::Rejected),
        };
        buf[0] = volume as u8;
        buf[1] = (volume >> 8) as u8;
        Some(InResponse::Accepted(&buf[..2]))
    }

    fn endpoint_get_request<'r>(&'r mut self, req: Request, buf: &'r mut [u8]) -> Option<InResponse<'r>> {
        let control_selector = (req.value >> 8) as u8;
        let endpoint_address = req.index as u8;

        if endpoint_address != self.streaming_endpoint_address {
            debug!("Unhandled endpoint get request for endpoint {}.", endpoint_address);
            return None;
        }

        if control_selector != SAMPLING_FREQ_CONTROL {
            debug!(
                "Unsupported endpoint get request for control selector {}.",
                control_selector
            );
            return Some(InResponse::Rejected);
        }

        let rates = &self.shared.sample_rates_hz;
        let sample_rate_hz = match req.request {
            GET_CUR => self.shared.sample_rate_hz.load(Ordering::Relaxed),
            GET_MIN => rates.iter().copied().min().unwrap_or(0),
            GET_MAX => rates.iter().copied().max().unwrap_or(0),
            // The rates are discrete; there is no step.
            GET_RES => 1,
            _ => return Some(InResponse::Rejected),
        };

        buf[0] = (sample_rate_hz & 0xFF) as u8;
        buf[1] = ((sample_rate_hz >> 8) & 0xFF) as u8;
        buf[2] = ((sample_rate_hz >> 16) & 0xFF) as u8;

        Some(InResponse::Accepted(&buf[..3]))
    }
}

impl<'d> Handler for Control<'d> {
    /// Called when the USB device has been enabled or disabled.
    fn enabled(&mut self, enabled: bool) {
        debug!("USB device enabled: {}", enabled);
    }

    /// Called when the host has set the address of the device to `addr`.
    fn addressed(&mut self, addr: u8) {
        debug!("Host set address to: {}", addr);
    }

    /// Called when the host has enabled or disabled the configuration of the device.
    fn configured(&mut self, configured: bool) {
        debug!("USB device configured: {}", configured);
    }

    /// Called when remote wakeup feature is enabled or disabled.
    fn remote_wakeup_enabled(&mut self, enabled: bool) {
        debug!("USB remote wakeup enabled: {}", enabled);
    }

    /// Called when a "set alternate setting" control request is done on the interface.
    fn set_alternate_setting(&mut self, iface: InterfaceNumber, alternate_setting: u8) {
        debug!(
            "USB set interface number {} to alt setting {}.",
            iface, alternate_setting
        );
    }

    /// Called after a USB reset after the bus reset sequence is complete.
    fn reset(&mut self) {
        let shared = self.shared;
        shared.audio_settings.lock(|x| x.set(AudioSettings::default()));
        shared
            .sample_rate_hz
            .store(shared.sample_rates_hz.first().copied().unwrap_or(0), Ordering::Relaxed);

        shared.changed.store(true, Ordering::Relaxed);
        shared.waker.wake();
    }

    /// Called when the bus has entered or exited the suspend state.
    fn suspended(&mut self, suspended: bool) {
        debug!("USB device suspended: {}", suspended);
    }

    // Handle control set requests.
    fn control_out(&mut self, req: control::Request, data: &[u8]) -> Option<OutResponse> {
        match req.request_type {
            RequestType::Class => match req.recipient {
                Recipient::Interface => self.interface_set_request(req, data),
                Recipient::Endpoint => self.endpoint_set_request(req, data),
                _ => None,
            },
            _ => None,
        }
    }

    // Handle control get requests.
    fn control_in<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        match req.request_type {
            RequestType::Class => match req.recipient {
                Recipient::Interface => self.interface_get_request(req, buf),
                Recipient::Endpoint => self.endpoint_get_request(req, buf),
                _ => None,
            },
            _ => None,
        }
    }
}

/// An audio function [UAC 3]: Input Terminal → [Feature Unit] → Output Terminal, carrying a PCM
/// stream of `channels` at `sample_width` and any of `sample_rates_hz`. One terminal is the USB stream.
pub(super) struct AudioFunction<'a> {
    pub channels: &'a [Channel],
    pub sample_width: SampleWidth,
    pub sample_rates_hz: &'a [u32],
    /// What the Input Terminal is.
    pub input_terminal: TerminalType,
    /// What the Output Terminal is.
    pub output_terminal: TerminalType,
    /// The Feature Unit's controls on the master channel and on each
    /// channel, or `None` for no Feature Unit at all.
    pub feature_unit: Option<(FeatureUnitControls, FeatureUnitControls)>,
}

/// Unit ids, unique within a function.
const INPUT_UNIT_ID: u8 = 0x01;
const FEATURE_UNIT_ID: u8 = 0x02;
const OUTPUT_UNIT_ID: u8 = 0x03;

/// Every class-specific descriptor has a 2-byte header on top of its body.
const DESCRIPTOR_HEADER_SIZE: usize = 2;

impl AudioFunction<'_> {
    /// Write the class-specific AudioControl interface descriptors [UAC 4.3.2]:
    /// the header, then each terminal and unit. `streaming_interface` is the
    /// AudioStreaming interface's number.
    pub(super) fn write_ac_interface_descriptors<'d, D: Driver<'d>>(
        &self,
        alt: &mut InterfaceAltBuilder<'_, 'd, D>,
        streaming_interface: u8,
    ) {
        // Input Terminal Descriptor [UAC 4.3.2.1]
        let terminal_type: u16 = self.input_terminal.into();
        let channel_config = self.channel_config();
        let input_terminal = [
            INPUT_TERMINAL, // bDescriptorSubtype
            INPUT_UNIT_ID,  // bTerminalID
            terminal_type as u8,
            (terminal_type >> 8) as u8, // wTerminalType
            0x00,                       // bAssocTerminal (none)
            self.channels.len() as u8,  // bNrChannels
            channel_config as u8,
            (channel_config >> 8) as u8, // wChannelConfig
            0x00,                        // iChannelNames (none)
            0x00,                        // iTerminal (none)
        ];

        // Feature Unit Descriptor [UAC 4.3.2.5]
        let mut feature_unit: Vec<u8, { 5 + MAX_AUDIO_CHANNEL_COUNT + 1 }> = Vec::new();
        if let Some((master, per_channel)) = self.feature_unit {
            feature_unit
                .extend_from_slice(&[
                    FEATURE_UNIT,    // bDescriptorSubtype (Feature Unit)
                    FEATURE_UNIT_ID, // bUnitID
                    INPUT_UNIT_ID,   // bSourceID
                    1,               // bControlSize (one byte per control)
                    master.bitmap(), // Master controls
                ])
                .unwrap();
            for _channel in self.channels {
                feature_unit.push(per_channel.bitmap()).unwrap();
            }
            feature_unit.push(0x00).unwrap(); // iFeature (none)
        }

        // Output Terminal Descriptor [UAC 4.3.2.2]
        let terminal_type: u16 = self.output_terminal.into();
        let output_terminal = [
            OUTPUT_TERMINAL, // bDescriptorSubtype
            OUTPUT_UNIT_ID,  // bTerminalID
            terminal_type as u8,
            (terminal_type >> 8) as u8, // wTerminalType
            0x00,                       // bAssocTerminal (none)
            // bSourceID: the feature unit, or the input terminal directly
            if self.feature_unit.is_some() {
                FEATURE_UNIT_ID
            } else {
                INPUT_UNIT_ID
            },
            0x00, // iTerminal (none)
        ];

        // Class-specific AC Interface Descriptor [UAC 4.3.2]; wTotalLength counts
        // itself and every unit, headers included.
        const HEADER_LEN: usize = 7;
        let total_length = [HEADER_LEN, input_terminal.len(), output_terminal.len()]
            .into_iter()
            .chain(self.feature_unit.map(|_| feature_unit.len()))
            .map(|len| len + DESCRIPTOR_HEADER_SIZE)
            .sum::<usize>();
        let header: [u8; HEADER_LEN] = [
            HEADER_SUBTYPE, // bDescriptorSubtype (Header)
            ADC_VERSION as u8,
            (ADC_VERSION >> 8) as u8, // bcdADC
            total_length as u8,
            (total_length >> 8) as u8, // wTotalLength
            0x01,                      // bInCollection (1 streaming interface)
            streaming_interface,       // baInterfaceNr
        ];

        alt.descriptor(CS_INTERFACE, &header);
        alt.descriptor(CS_INTERFACE, &input_terminal);
        if self.feature_unit.is_some() {
            alt.descriptor(CS_INTERFACE, &feature_unit);
        }
        alt.descriptor(CS_INTERFACE, &output_terminal);
    }

    /// Write the class-specific AudioStreaming interface descriptors [UAC 4.5.2]:
    /// the general one, linking to the USB streaming terminal, and the format.
    pub(super) fn write_as_interface_descriptors<'d, D: Driver<'d>>(&self, alt: &mut InterfaceAltBuilder<'_, 'd, D>) {
        // Class-specific AS Interface Descriptor: the stream connects to the USB terminal.
        let terminal_link = if self.input_terminal == TerminalType::UsbStreaming {
            INPUT_UNIT_ID
        } else {
            OUTPUT_UNIT_ID
        };
        alt.descriptor(
            CS_INTERFACE,
            &[
                AS_GENERAL,    // bDescriptorSubtype
                terminal_link, // bTerminalLink
                0x00,          // bDelay (none)
                PCM as u8,
                (PCM >> 8) as u8, // wFormatTag (PCM format)
            ],
        );

        // Type I Format Type Descriptor [UAC Formats 2.2.5]
        let mut format: Vec<u8, { 6 + 3 * MAX_SAMPLE_RATE_COUNT }> = Vec::from_slice(&[
            FORMAT_TYPE,                      // bDescriptorSubtype
            FORMAT_TYPE_I,                    // bFormatType
            self.channels.len() as u8,        // bNrChannels
            self.sample_width as u8,          // bSubframeSize
            self.sample_width.in_bit() as u8, // bBitResolution
            self.sample_rates_hz.len() as u8, // bSamFreqType (discrete)
        ])
        .unwrap();
        for sample_rate_hz in self.sample_rates_hz {
            assert!(*sample_rate_hz <= MAX_SAMPLE_RATE_HZ);
            format.extend_from_slice(&sample_rate_hz.to_le_bytes()[..3]).unwrap();
        }
        alt.descriptor(CS_INTERFACE, &format);
    }

    /// Write the isochronous audio data endpoint's descriptors: the standard
    /// one [UAC 4.6.1.1], pointing at the synch endpoint if there is one, and
    /// the class-specific one [UAC 4.6.1.2] with its sampling frequency control.
    pub(super) fn write_as_endpoint_descriptors<'d, D: Driver<'d>>(
        alt: &mut InterfaceAltBuilder<'_, 'd, D>,
        endpoint: &EndpointInfo,
        feedback: Option<&Feedback<'d, D>>,
    ) {
        alt.endpoint_descriptor(
            endpoint,
            SynchronizationType::Asynchronous,
            UsageType::DataEndpoint,
            &[
                0x00,                                     // bRefresh (0)
                feedback.map_or(0x00, Feedback::address), // bSynchAddress (the feedback endpoint, or none)
            ],
        );
        alt.descriptor(
            CS_ENDPOINT,
            &[
                AS_GENERAL,            // bDescriptorSubtype (General)
                SAMPLING_FREQ_CONTROL, // bmAttributes (support sampling frequency control)
                0x02,                  // bLockDelayUnits (PCM)
                0x0000 as u8,
                (0x0000 >> 8) as u8, // wLockDelay (0)
            ],
        );
    }

    /// The wChannelConfig bitmap. Panics on a duplicate channel.
    fn channel_config(&self) -> u16 {
        let mut channel_config: u16 = ChannelConfig::None.into();
        for channel in self.channels {
            let channel: u16 = channel.get_channel_config().into();

            if channel_config & channel != 0 {
                panic!("Invalid channel config, duplicate channel {}.", channel);
            }
            channel_config |= channel;
        }
        channel_config
    }
}

/// The isochronous synch endpoint [UAC 4.6.2]: used for writing sample rate
/// feedback to the host.
pub struct Feedback<'d, D: Driver<'d>> {
    feedback_endpoint: D::EndpointIn,
}

impl<'d, D: Driver<'d>> Feedback<'d, D> {
    /// Allocate the synch endpoint: isochronous IN, 24-bit packets.
    pub(super) fn allocate(alt: &mut InterfaceAltBuilder<'_, 'd, D>) -> Self {
        Self {
            feedback_endpoint: alt.alloc_endpoint_in(
                EndpointType::Isochronous,
                None,
                4, // Feedback packets are 24 bit (10.14 format).
                1,
            ),
        }
    }

    /// The endpoint's address, for the audio data endpoint's bSynchAddress.
    fn address(&self) -> u8 {
        self.feedback_endpoint.info().addr.into()
    }

    /// Write the endpoint's standard descriptor [UAC 4.6.2.1]. The class
    /// specification wants it after the audio data endpoint's, hence a
    /// separate step.
    pub(super) fn write_descriptor(&self, alt: &mut InterfaceAltBuilder<'_, 'd, D>, refresh: FeedbackRefresh) {
        alt.endpoint_descriptor(
            self.feedback_endpoint.info(),
            SynchronizationType::NoSynchronization,
            UsageType::FeedbackEndpoint,
            &[
                refresh as u8, // bRefresh
                0x00,          // bSynchAddress (none)
            ],
        );
    }

    /// Writes a single packet into the IN endpoint.
    pub async fn write_packet(&mut self, data: &[u8]) -> Result<(), EndpointError> {
        self.feedback_endpoint.write(data).await
    }

    /// Waits for the USB host to enable this interface.
    pub async fn wait_connection(&mut self) {
        self.feedback_endpoint.wait_enabled().await;
    }
}
