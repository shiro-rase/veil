use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;

pub fn render_qr_terminal(content: &str) -> Result<String> {
    let code = QrCode::new(content.as_bytes())?;
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    Ok(image)
}
