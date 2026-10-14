declare namespace Guacamole {
  class Status { code: number; message: string; }
  class Tunnel { state: number; uuid: string | null; oninstruction: ((opcode: string, args: string[]) => void) | null; onerror: ((status: Status) => void) | null; onstatechange: ((state: number) => void) | null; connect(data: string): void; disconnect(): void; sendMessage(...elements: (string | number)[]): void; setState(state: number): void; }
  class Parser { oninstruction: ((opcode: string, args: string[]) => void) | null; receive(text: string): void; }
  class Display { getElement(): HTMLElement; getWidth(): number; getHeight(): number; getScale(): number; scale(scale: number): void; showCursor(shown: boolean): void; flush(callback: () => void): void; onresize: ((width: number, height: number) => void) | null; }
  class InputStream { index: number; onblob: ((data: string) => void) | null; onend: (() => void) | null; sendAck(message: string, code: number): void; }
  class OutputStream { index: number; onack: ((status: Status) => void) | null; sendBlob(data: string): void; sendEnd(): void; }
  class ArrayBufferWriter { constructor(stream: OutputStream); blobLength: number; onack: ((status: Status) => void) | null; sendData(data: ArrayBuffer | Uint8Array): void; sendEnd(): void; }
  class Client { constructor(tunnel: Tunnel); onerror: ((status: Status) => void) | null; onstatechange: ((state: number) => void) | null; onclipboard: ((stream: InputStream, mimetype: string) => void) | null; createClipboardStream(mimetype: string): OutputStream; getDisplay(): Display; connect(data: string): void; disconnect(): void; sendKeyEvent(pressed: 0 | 1, keysym: number): void; sendMouseState(state: Mouse.State, applyDisplayScale?: boolean): void; sendSize(width: number, height: number): void; }
  class InputSink { getElement(): HTMLElement; focus(): void; }
  class Keyboard { constructor(element: HTMLElement); onkeydown: ((keysym: number) => boolean) | null; onkeyup: ((keysym: number) => void) | null; reset(): void; }
  namespace Mouse { class State { constructor(x?: number, y?: number, left?: boolean, middle?: boolean, right?: boolean, up?: boolean, down?: boolean); x: number; y: number; left: boolean; middle: boolean; right: boolean; up: boolean; down: boolean; } }
  class Mouse { constructor(element: HTMLElement); currentState: Mouse.State; onmousedown: ((state: Mouse.State) => void) | null; onmouseup: ((state: Mouse.State) => void) | null; onmousemove: ((state: Mouse.State) => void) | null; onmouseout: (() => void) | null; }
}
