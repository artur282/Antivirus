from PIL import Image
import os

source = Image.open("img/icono.png").convert("RGBA")
os.makedirs("src-tauri/icons", exist_ok=True)
for size, name in [
    (32, "32x32.png"),
    (128, "128x128.png"),
    (256, "128x128@2x.png"),
    (512, "icon.png"),
]:
    source.resize((size, size), Image.Resampling.LANCZOS).save(
        f"src-tauri/icons/{name}"
    )
source.resize((256, 256), Image.Resampling.LANCZOS).save(
    "src-tauri/icons/icon.ico",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
)
print("icons generated")
