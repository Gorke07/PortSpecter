use iced::widget::button;
use iced::widget::container;
use iced::{Background, Border, Color, Theme};
pub const ACCENT: Color = Color::from_rgb(0.263, 0.839, 0.773);
pub const MUTED: Color = Color::from_rgb(0.651, 0.702, 0.741);
pub const GREEN: Color = Color::from_rgb(0.404, 0.851, 0.627);
pub const AMBER: Color = Color::from_rgb(0.949, 0.776, 0.427);
pub const RED: Color = Color::from_rgb(0.941, 0.502, 0.502);
pub const MONO: iced::Font = iced::Font::with_name("JetBrains Mono");
pub fn muted(theme: &Theme) -> Color {
    if theme.extended_palette().is_dark {
        MUTED
    } else {
        Color::from_rgb8(85, 102, 113)
    }
}
pub fn inspector_tab(theme: &Theme, status: button::Status) -> button::Style {
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    button::Style {
        background: hovered.then(|| theme.extended_palette().background.strong.color.into()),
        text_color: muted(theme),
        border: Border {
            radius: 4.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}
pub fn inspector_tab_active(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    button::Style {
        background: Some(
            if p.is_dark {
                p.background.strong.color
            } else {
                p.primary.weak.color
            }
            .into(),
        ),
        text_color: theme.palette().primary,
        ..inspector_tab(theme, status)
    }
}
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
            background: Color::from_rgb8(245, 246, 248),
            text: Color::from_rgb8(30, 38, 45),
            primary: Color::from_rgb8(11, 110, 99),
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
    if light {
        Theme::custom_with_fn("PortSpecter Light", palette, |palette| {
            use iced::theme::palette::Pair;
            let mut extended = iced::theme::palette::Extended::generate(palette);
            // Explicit neutral surfaces avoid hue shifts in the generated light palette.
            let pair = |r, g, b| Pair::new(Color::from_rgb8(r, g, b), palette.text);
            extended.background.base = pair(245, 246, 248);
            extended.background.weakest = pair(255, 255, 255);
            extended.background.weaker = pair(250, 251, 252);
            extended.background.weak = pair(255, 255, 255);
            extended.background.neutral = pair(237, 240, 243);
            extended.background.strong = pair(207, 214, 220);
            extended.background.stronger = pair(145, 157, 168);
            extended.background.strongest = pair(91, 106, 118);
            extended.secondary.base = pair(91, 106, 118);
            extended.secondary.weak = pair(224, 229, 233);
            extended.secondary.strong = pair(65, 79, 91);
            extended.primary.weak = Pair::new(Color::from_rgb8(226, 242, 237), palette.primary);
            extended.primary.strong = Pair::new(Color::from_rgb8(7, 86, 78), Color::WHITE);
            extended
        })
    } else {
        Theme::custom("PortSpecter", palette)
    }
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
        background: Some(
            if p.is_dark {
                p.background.weak.color
            } else {
                Color::from_rgb8(237, 240, 243)
            }
            .into(),
        ),
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
                Color::from_rgb8(232, 245, 240)
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
                if p.is_dark {
                    p.background.strong.color
                } else {
                    p.background.neutral.color
                }
            } else {
                p.background.weak.color
            }
            .into(),
        ),
        text_color: if matches!(status, button::Status::Disabled) {
            muted(theme)
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
