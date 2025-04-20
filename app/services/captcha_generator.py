import random
import string
from io import BytesIO
from typing import Tuple

from PIL import Image, ImageDraw, ImageFilter, ImageFont


def generate_captcha_text(length: int = 5) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def generate_captcha_image(captcha_text: str) -> BytesIO:
    img: Image.Image = Image.new("RGB", (150, 50), color=(255, 255, 255))
    draw: ImageDraw.ImageDraw = ImageDraw.Draw(img)

    try:
        font: ImageFont.FreeTypeFont = ImageFont.truetype("arial.ttf", 40)
    except IOError:
        font = ImageFont.load_default()

    for i, char in enumerate(captcha_text):
        x: int = 10 + i * 25 + random.randint(-5, 5)
        y: int = random.randint(0, 10)
        draw.text((x, y), char, font=font, fill=(0, 0, 0))

    for _ in range(5):
        start_point: Tuple[int, int] = (random.randint(0, 150), random.randint(0, 50))
        end_point: Tuple[int, int] = (random.randint(0, 150), random.randint(0, 50))
        draw.line([start_point, end_point], fill=(0, 0, 0), width=2)

    for _ in range(30):
        x: int = random.randint(0, 150)
        y: int = random.randint(0, 50)
        draw.point((x, y), fill=(0, 0, 0))

    img = img.filter(ImageFilter.GaussianBlur(1))

    img = img.transform(
        (150, 50),
        Image.AFFINE,
        (1, random.uniform(-0.3, 0.3), 0, random.uniform(-0.1, 0.1), 1, 0),
        Image.BILINEAR,
    )

    img_io: BytesIO = BytesIO()
    img.save(img_io, "PNG")
    img_io.seek(0)

    return img_io
