import { afterEach, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'

enableAutoUnmount(afterEach)
Object.defineProperty(window, 'matchMedia', { writable: true, value: vi.fn().mockImplementation(query => ({matches: false, media: query, onchange: null, addListener: vi.fn(), removeListener: vi.fn(), addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn()})) })
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} }
Object.defineProperty(window,'scrollTo',{configurable:true,value:vi.fn()})
// JSDOM 不计算伪元素；真实布局尺寸由浏览器验收核对。
const readComputedStyle=window.getComputedStyle.bind(window)
window.getComputedStyle=(element:Element)=>readComputedStyle(element)
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); document.body.replaceChildren() })
