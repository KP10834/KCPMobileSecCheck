import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var flutterViewControllerRef: FlutterViewController?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    flutterViewControllerRef = flutterViewController
    let windowFrame = self.frame
    self.contentViewController = nil
    self.setFrame(windowFrame, display: true)

    contentView = DropView(
      frame: contentView?.frame ?? .zero,
      channel: FlutterMethodChannel(
        name: "kcp_mobile_sec_check/drop",
        binaryMessenger: flutterViewController.engine.binaryMessenger
      ),
      flutterView: flutterViewController.view
    )
    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}

final class DropView: NSView {
  private let channel: FlutterMethodChannel
  private let flutterView: NSView

  init(frame: NSRect, channel: FlutterMethodChannel, flutterView: NSView) {
    self.channel = channel
    self.flutterView = flutterView
    super.init(frame: frame)
    autoresizingMask = [.width, .height]
    registerForDraggedTypes([.fileURL])
    addSubview(flutterView)
    flutterView.frame = bounds
    flutterView.autoresizingMask = [.width, .height]
  }

  required init?(coder: NSCoder) {
    fatalError("init(coder:) has not been implemented")
  }

  override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
    channel.invokeMethod("dragEntered", arguments: nil)
    return .copy
  }

  override func draggingExited(_ sender: NSDraggingInfo?) {
    channel.invokeMethod("dragExited", arguments: nil)
  }

  override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
    guard
      let item = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self])?.first as? URL
    else {
      channel.invokeMethod("dragExited", arguments: nil)
      return false
    }
    channel.invokeMethod("fileDropped", arguments: item.path)
    return true
  }
}
