from os import path
from config import *
from pathlib import Path
from PIL import Image


def prevw(file):

    file_path = DOWNLOADS_FOLDER_NAME+"\\"+file

    if not path.exists(file_path):
        return "Sorry, cant find such file."

    ext = path.splitext(file)[-1]

    if ext in (".png", ".jpg", ".jpeg"):
        return img_to_ascii(file_path)

    else:
        return Path(file_path).read_text("utf-8")


def img_to_ascii(img_path):
    grayscale_chars = " .,:;i1tfLCG08@"
    grayscale_chars = grayscale_chars[::-1]
    ascii_art = []
    with Image.open(img_path) as img:
        img = img.convert("L")
        img = img.resize(IMG_CROP_SIZE)
        for y in range(IMG_CROP_SIZE[1]):
            row = ""
            for x in range(IMG_CROP_SIZE[0]):
                pixel = img.getpixel((x, y))
                char = grayscale_chars[int(
                    (pixel/255)*len(grayscale_chars))]
                row += char
            row += "\n"
            ascii_art.append(row)
    return "".join(ascii_art)
