//! USB Audio Class 1.0 - Audio source device (device to host), e.g. a microphone.
//!
//! Configured through [`Config`]; built and used like [`super::speaker::Speaker`].

pub use super::Volume;
use super::class_codes::*;
use super::function::{AudioFunction, MAX_SAMPLE_RATE_COUNT};
pub use super::function::{AudioSettings, ControlMonitor, FeatureUnitControls, Feedback, State};
use super::terminal_type::TerminalType;
use super::{Channel, FeedbackRefresh, MAX_AUDIO_CHANNEL_INDEX, SampleWidth};
use crate::Builder;
use crate::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointType};

/// Everything the audio source advertises to the host.
#[derive(Clone, Copy)]
pub struct Config<'d> {
    /// The supported sample rates in Hz, as discrete values. At least one, at
    /// most ten. The first is the one reported before the host sets any.
    pub sample_rates_hz: &'d [u32],
    /// The audio sample resolution.
    pub sample_width: SampleWidth,
    /// The audio channels, in stream order (up to 12). Entries must be unique.
    /// One entry is a mono stream.
    pub channels: &'d [Channel],
    /// What the Input Terminal is; the host shows the device by it.
    pub input_terminal: TerminalType,
    /// Which Feature Unit controls the host gets; [`FeatureUnitControls::NONE`]
    /// leaves the Feature Unit out of the function altogether.
    pub feature_unit: FeatureUnitControls,
    /// Whether a synch (feedback) endpoint is allocated beside the stream, and
    /// how often the host should read it. A source rarely wants one — its
    /// stream is declared asynchronous either way, and the host follows its rate.
    pub feedback: Option<FeedbackRefresh>,
}

impl<'d> Config<'d> {
    /// A microphone with a mute control, no volume control and no feedback
    /// endpoint: the common case.
    pub const fn new(sample_rates_hz: &'d [u32], sample_width: SampleWidth, channels: &'d [Channel]) -> Self {
        Self {
            sample_rates_hz,
            sample_width,
            channels,
            input_terminal: TerminalType::InMicrophone,
            feature_unit: FeatureUnitControls {
                mute: true,
                volume: false,
            },
            feedback: None,
        }
    }
}

/// Implementation of the USB audio class 1.0, source side.
pub struct AudioSource<'d, D: Driver<'d>> {
    /// The audio stream toward the host.
    pub stream: Stream<'d, D>,
    /// The synch (feedback) endpoint, if [`Config::feedback`] asked for one.
    pub feedback: Option<Feedback<'d, D>>,
    /// Control Monitor
    pub control_monitor: ControlMonitor<'d>,
}

impl<'d, D: Driver<'d>> AudioSource<'d, D> {
    /// Creates a new [`AudioSource`] device, and registers its control handler.
    ///
    /// The streaming endpoint's packet size is one full-speed frame (1 ms) of
    /// samples at the highest sample rate, plus one sample: the source's clock
    /// is its own, and it is allowed to get a sample ahead of the host.
    ///
    /// # Panics
    ///
    /// If `config` has no sample rate or more than ten, no channel or more
    /// than twelve, a duplicate channel, or a sample rate above 24 bits.
    pub fn new(builder: &mut Builder<'d, D>, state: &'d mut State<'d>, config: Config<'d>) -> Self {
        let Config {
            sample_rates_hz,
            sample_width,
            channels,
            input_terminal,
            feature_unit,
            feedback,
        } = config;
        assert!(
            (1..=MAX_SAMPLE_RATE_COUNT).contains(&sample_rates_hz.len()),
            "between one and ten sample rates"
        );
        assert!(
            (1..=MAX_AUDIO_CHANNEL_INDEX).contains(&channels.len()),
            "between one and twelve channels"
        );

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
        // Input terminal (e.g. a microphone) -> [Feature Unit (mute and volume)] -> Output terminal (USB stream)
        let function = AudioFunction {
            channels,
            sample_width,
            sample_rates_hz,
            input_terminal,
            output_terminal: TerminalType::UsbStreaming,
            // The Feature Unit only if any control was asked for; the same controls on the master and every channel.
            feature_unit: (feature_unit != FeatureUnitControls::NONE).then_some((feature_unit, feature_unit)),
        };
        function.write_ac_interface_descriptors(&mut alt, streaming_interface);

        // Audio streaming interface [UAC 4.5.1]: alternate setting 0 is zero-bandwidth
        // and has nothing in it; alternate setting 1 carries the stream.
        let mut interface = func.interface();
        interface.alt_setting(USB_AUDIO_CLASS, USB_AUDIOSTREAMING_SUBCLASS, PROTOCOL_NONE, None);
        let mut alt = interface.alt_setting(USB_AUDIO_CLASS, USB_AUDIOSTREAMING_SUBCLASS, PROTOCOL_NONE, None);

        function.write_as_interface_descriptors(&mut alt);

        // One millisecond of samples at the fastest rate, plus one sample of slack.
        let frame_bytes = channels.len() as u32 * sample_width as u32;
        let max_rate = sample_rates_hz.iter().copied().max().unwrap_or(0);
        let max_packet_size = ((max_rate * frame_bytes).div_ceil(1000) + frame_bytes) as u16;

        let streaming_endpoint = alt.alloc_endpoint_in(EndpointType::Isochronous, None, max_packet_size, 1);
        let feedback = feedback.map(|refresh| (Feedback::allocate(&mut alt), refresh));
        // The audio data endpoint's descriptors point at the synch endpoint; the synch endpoint's go after.
        AudioFunction::write_as_endpoint_descriptors(
            &mut alt,
            streaming_endpoint.info(),
            feedback.as_ref().map(|(feedback, _)| feedback),
        );
        if let Some((feedback, refresh)) = &feedback {
            feedback.write_descriptor(&mut alt, *refresh);
        }

        // Free up the builder.
        drop(func);

        let control_monitor = state.register(
            builder,
            channels,
            sample_rates_hz,
            feature_unit,
            control_interface,
            streaming_endpoint.info().addr.into(),
        );

        Self {
            stream: Stream { streaming_endpoint },
            feedback: feedback.map(|(feedback, _)| feedback),
            control_monitor,
        }
    }
}

/// Used for writing audio frames.
pub struct Stream<'d, D: Driver<'d>> {
    streaming_endpoint: D::EndpointIn,
}

impl<'d, D: Driver<'d>> Stream<'d, D> {
    /// Writes a single packet into the IN endpoint
    pub async fn write_packet(&mut self, data: &[u8]) -> Result<(), EndpointError> {
        self.streaming_endpoint.write(data).await
    }

    /// Waits for the USB host to enable this interface: it is listening.
    pub async fn wait_connection(&mut self) {
        self.streaming_endpoint.wait_enabled().await;
    }
}
