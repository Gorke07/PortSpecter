#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
mod locale;
mod style;
#[cfg(windows)]
mod windows_icon;

fn main() -> iced::Result {
    #[cfg(windows)]
    if portspecter_platform::shares::helper_main() {
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    iced::application(app::App::new, app::App::update, app::App::view)
        .title("PortSpecter")
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .font(include_bytes!("../../../assets/fonts/Inter.ttf").as_slice())
        .font(include_bytes!("../../../assets/fonts/JetBrainsMono.ttf").as_slice())
        .default_font(iced::Font::with_name("Inter"))
        .window(iced::window::Settings {
            size: iced::Size::new(1440., 960.),
            min_size: Some(iced::Size::new(1024., 700.)),
            decorations: false,
            exit_on_close_request: false,
            icon: Some(application_icon()),
            ..Default::default()
        })
        .centered()
        .run()
}

fn application_icon() -> iced::window::Icon {
    let pixels = image::load_from_memory(include_bytes!(
        "../../../assets/icons/portspecter-macos.png"
    ))
    .expect("Bundled application icon is valid PNG")
    .resize(256, 256, image::imageops::FilterType::Lanczos3)
    .into_rgba8();
    let (width, height) = pixels.dimensions();
    iced::window::icon::from_rgba(pixels.into_raw(), width, height)
        .expect("Application icon is RGBA")
}
