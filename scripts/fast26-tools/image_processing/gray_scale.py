import ops
from PIL import Image
from time import time

Image.MAX_IMAGE_PIXELS = None

def image_processing(file_name, image_path):
    path_list = []
    start = time()
    with Image.open(image_path) as image:
        tmp = image
        # path_list += ops.flip(image, file_name)
        # path_list += ops.rotate(image, file_name)
        # path_list += ops.filter(image, file_name)
        path_list += ops.gray_scale(image, file_name)
        # path_list += ops.resize(image, file_name)

    latency = time() - start
    return latency, path_list


if __name__ == '__main__':
	latency, _ = image_processing("result.png", "input.png")
	print(f"image processing latency: {latency}")
