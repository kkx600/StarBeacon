import { checkGallery, galleryDirectory, viewport } from './screenshot-gallery.mjs'

try {
  const count = await checkGallery(galleryDirectory)
  console.log(`截图清单核对通过，${count} 张 ${viewport.width}×${viewport.height} JPEG 齐全。`)
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
