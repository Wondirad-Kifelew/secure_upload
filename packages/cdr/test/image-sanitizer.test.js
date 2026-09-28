import sharp from "sharp";
import { createImageSanitizer, ImageSanitizer } from "../src/image-sanitizer.js";

async function pngWithExif() {
  return sharp({
    create: { width: 20, height: 20, channels: 3, background: { r: 255, g: 0, b: 0 } },
  })
    .withMetadata({ exif: { IFD0: { Copyright: "test copyright tag" } } })
    .png()
    .toBuffer();
}

async function plainPng() {
  return sharp({
    create: { width: 10, height: 10, channels: 3, background: { r: 0, g: 0, b: 255 } },
  })
    .png()
    .toBuffer();
}

describe("ImageSanitizer", () => {
  test("has the expected Sanitizer shape", () => {
    expect(ImageSanitizer.name).toBe("Image Sanitizer");
    expect(typeof ImageSanitizer.sanitize).toBe("function");
  });

  test("strips EXIF metadata from a real image that has it", async () => {
    const original = await pngWithExif();
    const originalMeta = await sharp(original).metadata();
    expect(originalMeta.exif).toBeDefined();

    const result = await ImageSanitizer.sanitize(original);
    const sanitizedMeta = await sharp(result.buffer).metadata();

    expect(sanitizedMeta.exif).toBeUndefined();
    expect(result.findings.some((f) => f.rule === "image-exif-stripped")).toBe(true);
  });

  test("a plain image with no metadata produces no findings", async () => {
    const original = await plainPng();
    const result = await ImageSanitizer.sanitize(original);
    expect(result.findings).toEqual([]);
  });

  test("preserves the actual visible image content (same dimensions)", async () => {
    const original = await plainPng();
    const originalMeta = await sharp(original).metadata();

    const result = await ImageSanitizer.sanitize(original);
    const sanitizedMeta = await sharp(result.buffer).metadata();

    expect(sanitizedMeta.width).toBe(originalMeta.width);
    expect(sanitizedMeta.height).toBe(originalMeta.height);
  });

  test("defeats a payload hidden after the real image data", async () => {
    const original = await plainPng();
    const marker = "malicious-test-string-for-yara-testing";
    const withHiddenPayload = Buffer.concat([original, Buffer.from(marker)]);

    const result = await ImageSanitizer.sanitize(withHiddenPayload);

    expect(result.buffer.includes(marker)).toBe(false);
  });

  test("the sanitized output is still a genuinely valid, decodable image", async () => {
    const original = await pngWithExif();
    const result = await ImageSanitizer.sanitize(original);

    await expect(sharp(result.buffer).metadata()).resolves.toBeDefined();
  });

  test("throws a clear error for a buffer that isn't a real image", async () => {
    await expect(
      ImageSanitizer.sanitize(Buffer.from("this is not an image at all"))
    ).rejects.toThrow(/Could not decode image/);
  });

  test("createImageSanitizer can force a specific output format", async () => {
    const original = await plainPng();
    const sanitizer = createImageSanitizer({ outputFormat: "jpeg" });

    const result = await sanitizer.sanitize(original);
    const outputMeta = await sharp(result.buffer).metadata();

    expect(outputMeta.format).toBe("jpeg");
  });
});