from PIL import Image

img = Image.open("a.jpg")
img_resized = img.resize((8900, 8900))
img_resized.save("resized.jpg")
