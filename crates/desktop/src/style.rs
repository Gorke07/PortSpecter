use iced::widget::button;
use iced::widget::container;
use iced::{Background, Border, Color, Theme};
pub const ACCENT: Color = Color::from_rgb(0.263, 0.839, 0.773);
pub const MUTED: Color = Color::from_rgb(0.651, 0.702, 0.741);
pub const GREEN: Color = Color::from_rgb(0.404, 0.851, 0.627);
pub const AMBER: Color = Color::from_rgb(0.949, 0.776, 0.427);
pub const RED: Color = Color::from_rgb(0.941, 0.502, 0.502);
pub const MONO: iced::Font = iced::Font::with_name("JetBrains Mono");
pub fn window_control(theme: &Theme, status: button::Status, close: bool) -> button::Style {
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    button::Style {
        background: if hovered {
            Some(
                if close {
                    Color::from_rgb8(190, 48, 57)
                } else {
                    theme.extended_palette().background.strong.color
                }
                .into(),
            )
        } else {
            None
        },
        text_color: if hovered && close {
            Color::WHITE
        } else {
            theme.palette().text
        },
        ..Default::default()
    }
}
pub fn theme(light: bool) -> Theme {
    let palette = if light {
        iced::theme::Palette {
            background: Color::from_rgb8(242, 245, 247),
            text: Color::from_rgb8(25, 36, 43),
            primary: Color::from_rgb8(16, 119, 109),
            success: Color::from_rgb8(29, 125, 80),
            warning: Color::from_rgb8(139, 92, 9),
            danger: Color::from_rgb8(179, 47, 47),
        }
    } else {
        iced::theme::Palette {
            background: Color::from_rgb8(16, 19, 22),
            text: Color::from_rgb8(237, 243, 246),
            primary: ACCENT,
            success: GREEN,
            warning: AMBER,
            danger: RED,
        }
    };
    Theme::custom("PortSpecter", palette)
}
pub fn surface(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.background.weak.color)),
        border: Border {
            color: p.background.strong.color,
            width: 1.,
            radius: 8.into(),
        },
        ..Default::default()
    }
}
pub fn sidebar(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(p.background.weak.color.into()),
        ..Default::default()
    }
}
pub fn selected(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(
            if p.is_dark {
                Color::from_rgb8(23, 56, 51)
            } else {
                Color::from_rgb8(217, 241, 236)
            }
            .into(),
        ),
        border: Border {
            color: p.primary.base.color,
            width: 1.,
            radius: 6.into(),
        },
        ..Default::default()
    }
}
pub fn subtle(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        border: Border {
            color: p.background.strong.color,
            width: 1.,
            radius: 6.into(),
        },
        ..Default::default()
    }
}

pub fn secondary(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    button::Style {
        background: Some(
            if hovered {
                p.background.strong.color
            } else {
                p.background.weak.color
            }
            .into(),
        ),
        text_color: if matches!(status, button::Status::Disabled) {
            p.background.strong.text
        } else {
            p.background.base.text
        },
        border: Border {
            color: p.background.strong.color,
            width: 1.,
            radius: 6.into(),
        },
        ..Default::default()
    }
}
