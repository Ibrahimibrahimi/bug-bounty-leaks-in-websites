def build_image_url(
    base_url: str = "https://example.com/images",
    asset_id: str = "510572149",
    file_hash: str = "814de8b7",
    width: int = 160,
    height: int = 160,
    mode: str = "o",
    signature: str = "53bb7393a62c",
    dpi_scale: int = 2
) -> str:
    """
    Build an image transformation URL.

    Format: {base_url}/{asset_id}.{file_hash}.{width}x{height}{mode}.{signature}@{dpi_scale}x

    Args:
        base_url    : Base URL of the image CDN/server
        asset_id    : Numeric asset/resource ID
        file_hash   : CRC32/hash fingerprint of the file
        width       : Image width in pixels
        height      : Image height in pixels
        mode        : Crop/fit mode flag (o, c, f, s, b...)
        signature   : HMAC security token
        dpi_scale   : Retina multiplier (1, 2, 3...)

    Returns:
        Full image URL string
    """
    filename = f"{asset_id}.{file_hash}.{width}x{height}{mode}.{signature}@{dpi_scale}x"
    return f"{base_url}/{filename}"


# --- Usage ---

# Default (mirrors the original string you found)
print(build_image_url())
# https://example.com/images/510572149.814de8b7.160x160o.53bb7393a62c@2x

# Custom dimensions
print(build_image_url(width=320, height=320))
# https://example.com/images/510572149.814de8b7.320x320o.53bb7393a62c@2x

# Different asset
print(build_image_url(asset_id="510572150", file_hash="cafe1234"))
# https://example.com/images/510572150.cafe1234.160x160o.53bb7393a62c@2x

# Full custom
print(build_image_url(
    height=888888888,
    width=88888888
))
# https://cdn.target.com/media/987654321.aabbccdd.800x600c.ff00aa112233@1x
