use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn fetch_html(wallet: String) -> Result<String, JsValue> {
    Ok(format!("test1--{wallet}"))
}
