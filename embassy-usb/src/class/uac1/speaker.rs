//! USB Audio Class 1.0 - Speaker device
//!
//! Provides a class with a single audio streaming interface (host to device),
//! that advertises itself as a speaker. Includes explicit sample rate feedback.
//!
//! Various aspects of the audio stream can be configured, for example:
//! - sample rate
//! - sample resolution
//! - audio channel count and assignment
//!
//! The class provides volume and mute controls for each channel.

pub use super::Volume;
use super::class_codes::*;
use super::function::{AudioFunction, FeatureUnitControls};
pub use super::function::{AudioSettings, ControlMonitor, Feedback, State};
use super::terminal_type::TerminalType;
use super::{Channel, FeedbackRefresh, SampleWidth};
use crate::Builder;
use crate::driver::{Driver, Endpoint, EndpointError, EndpointOut, EndpointType};

/// Implementation of the USB audio class 1.0.
pub struct Speaker<'d, D: Driver<'d>> {
    /// Stream
    pub stream: Stream<'d, D>,
    /// Feedback
    pub feedback: Feedback<'d, D>,
    /// Control Monitor
    pub control_monitor: ControlMonitor<'d>,
}

impl<'d, D: Driver<'d>> Speaker<'d, D> {
    /// Creates a new [`Speaker`] device, split into a stream, feedback, and a control change notifier.
    ///
    /// The packet size should be chosen, based on the expected transfer size of samples per (micro)frame.
    /// For example, a stereo stream at 32 bit resolution and 48 kHz sample rate yields packets of 384 byte for
    /// full-speed USB (1 ms frame interval) or 48 byte for high-speed USB (125 us microframe interval).
    /// When using feedback, the packet size varies and thus, the `max_packet_size` should be increased (e.g. to double).
    ///
    /// # Arguments
    ///
    /// * `builder` - The builder for the class.
    /// * `state` - The internal state of the class.
    /// * `max_packet_size` - The maximum packet size per (micro)frame.
    /// * `resolution` - The audio sample resolution.
    /// * `sample_rates_hz` - The supported sample rates in Hz (at most ten).
    /// * `channels` - The advertised audio channels (up to 12). Entries must be unique, or this function panics.
    /// * `feedback_refresh_period` - The refresh period for the feedback value.
    pub fn new(
        builder: &mut Builder<'d, D>,
        state: &'d mut State<'d>,
        max_packet_size: u16,
        resolution: SampleWidth,
        sample_rates_hz: &[u32],
        channels: &'d [Channel],
        feedback_refresh_period: FeedbackRefresh,
    ) -> Self {
        // The class and subclass fields of the IAD aren't required to match the class and subclass fields of
        // the interfaces in the interface collection that the IAD describes. Microsoft recommends that
        // the first interface of the collection has class and subclass fields that match the class and
        // subclass fields of the IAD.
        let mut func = builder.function(USB_AUDIO_CLASS, USB_AUDIOCONTROL_SUBCLASS, PROTOCOL_NONE);

        // Audio control interface (mandatory) [UAC 4.3.1]
        let mut interface = func.interface();
        let control_interface = interface.interface_number();
        let streaming_interface = u8::from(control_interface) + 1;
        let mut alt = interface.alt_setting(USB_AUDIO_CLASS, USB_AUDIOCONTROL_SUBCLASS, PROTOCOL_NONE, None);

        // Terminal topology:
        // Input terminal (receives audio stream) -> Feature Unit (mute and volume) -> Output terminal (e.g. towards speaker)
        let function = AudioFunction {
            channels,
            sample_width: resolution,
            sample_rates_hz,
            input_terminal: TerminalType::UsbStreaming,
            output_terminal: TerminalType::OutSpeaker,
            // Mute and volume control on every channel; the master channel has none of its own.
            feature_unit: Some((FeatureUnitControls::NONE, FeatureUnitControls::ALL)),
        };
        function.write_ac_interface_descriptors(&mut alt, streaming_interface);

        // Audio streaming interface [UAC 4.5.1]: alternate setting 0 is zero-bandwidth
        // and has nothing in it; alternate setting 1 carries the stream.
        let mut interface = func.interface();
        interface.alt_setting(USB_AUDIO_CLASS, USB_AUDIOSTREAMING_SUBCLASS, PROTOCOL_NONE, None);
        let mut alt = interface.alt_setting(USB_AUDIO_CLASS, USB_AUDIOSTREAMING_SUBCLASS, PROTOCOL_NONE, None);

        function.write_as_interface_descriptors(&mut alt);

        let streaming_endpoint = alt.alloc_endpoint_out(EndpointType::Isochronous, None, max_packet_size, 1);
        let feedback = Feedback::allocate(&mut alt);
        // The audio data endpoint's descriptors point at the synch endpoint; the synch endpoint's go after.
        AudioFunction::write_as_endpoint_descriptors(&mut alt, streaming_endpoint.info(), Some(&feedback));
        feedback.write_descriptor(&mut alt, feedback_refresh_period);

        // Free up the builder.
        drop(func);

        let control_monitor = state.register(
            builder,
            channels,
            sample_rates_hz,
            FeatureUnitControls::ALL,
            control_interface,
            streaming_endpoint.info().addr.into(),
        );

        Self {
            stream: Stream { streaming_endpoint },
            feedback,
            control_monitor,
        }
    }
}

/// Used for reading audio frames.
pub struct Stream<'d, D: Driver<'d>> {
    streaming_endpoint: D::EndpointOut,
}

impl<'d, D: Driver<'d>> Stream<'d, D> {
    /// Reads a single packet from the OUT endpoint
    pub async fn read_packet(&mut self, data: &mut [u8]) -> Result<usize, EndpointError> {
        self.streaming_endpoint.read(data).await
    }

    /// Waits for the USB host to enable this interface
    pub async fn wait_connection(&mut self) {
        self.streaming_endpoint.wait_enabled().await;
    }
}
