import SwiftUI
import AVFoundation

/// IPA-D22: simple `AVCaptureSession`-based QR scanner sheet.
///
/// Presented modally from `EndpointsView.Scan` buttons. Validates the
/// scanned payload against `^tamizdat://` (or `^samizdat://` legacy)
/// and fires `onScan` exactly once before dismissing.
///
/// Permissions: requires `NSCameraUsageDescription` in Info.plist
/// (added in IPA-D22). When the user denies camera access the sheet
/// shows an inline message with a "Open iOS Settings" button.
struct QRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    /// Called once with the validated scanned string (still includes
    /// the `tamizdat://` / `samizdat://` prefix). Caller is responsible
    /// for parsing further and persisting.
    let onScan: (String) -> Void

    @State private var permissionStatus: AVAuthorizationStatus = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var lastError: String?

    var body: some View {
        ZStack {
            theme.bg.ignoresSafeArea()

            VStack(spacing: 0) {
                // Header (matches the Endpoints/Settings sheet pattern)
                HStack {
                    Chip(label: "Cancel") { dismiss() }
                    Spacer()
                    Text("Scan QR")
                        .font(.geist(.semibold, size: 16))
                        .foregroundStyle(theme.text)
                    Spacer()
                    // Spacer to balance the leading chip
                    Color.clear.frame(width: 64, height: 1)
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 6)

                Text("Scan a tamizdat:// QR")
                    .font(.geist(.bold, size: 22))
                    .tracking(-0.66)
                    .foregroundStyle(theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 12)

                Group {
                    switch permissionStatus {
                    case .authorized:
                        scannerView
                    case .notDetermined:
                        permissionPrompt
                    case .denied, .restricted:
                        permissionDenied
                    @unknown default:
                        permissionDenied
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.horizontal, 16)
                .padding(.bottom, 18)
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .onAppear {
            permissionStatus = AVCaptureDevice.authorizationStatus(for: .video)
        }
    }

    private var scannerView: some View {
        ZStack {
            QRScannerRepresentable(onScan: { code in
                let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.hasPrefix("tamizdat://") || trimmed.hasPrefix("samizdat://") {
                    onScan(trimmed)
                    dismiss()
                } else {
                    lastError = "Not a tamizdat:// link"
                }
            })
            .clipShape(RoundedRectangle(cornerRadius: 22))
            .overlay(
                RoundedRectangle(cornerRadius: 22)
                    .strokeBorder(theme.cardBorder, lineWidth: 0.5)
            )

            // Reticle hint
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(theme.mint.opacity(0.6), lineWidth: 2)
                .frame(width: 220, height: 220)

            if let err = lastError {
                VStack {
                    Spacer()
                    Text(err)
                        .font(.geist(.medium, size: 13))
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .background(Capsule().fill(theme.redDim))
                        .foregroundStyle(theme.red)
                        .padding(.bottom, 16)
                }
            }
        }
    }

    private var permissionPrompt: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                Text("Camera access")
                    .font(.geist(.semibold, size: 16))
                    .foregroundStyle(theme.text)
                Text("Tamizdat needs camera access to scan tamizdat:// QR codes for endpoint setup.")
                    .font(.geist(.regular, size: 13))
                    .foregroundStyle(theme.textDim)
                Button {
                    AVCaptureDevice.requestAccess(for: .video) { granted in
                        DispatchQueue.main.async {
                            permissionStatus = granted ? .authorized : .denied
                        }
                    }
                } label: {
                    Text("Allow camera")
                        .font(.geist(.semibold, size: 14))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.mint)
                        .foregroundStyle(theme.mintInk)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var permissionDenied: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                Text("Camera blocked")
                    .font(.geist(.semibold, size: 16))
                    .foregroundStyle(theme.text)
                Text("Camera access is denied for Tamizdat. Open iOS Settings to grant permission, then try again.")
                    .font(.geist(.regular, size: 13))
                    .foregroundStyle(theme.textDim)
                Button {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    Text("Open iOS Settings")
                        .font(.geist(.semibold, size: 14))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.blue)
                        .foregroundStyle(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .buttonStyle(.plain)
            }
        }
    }
}

// MARK: – UIViewControllerRepresentable wrapper around AVCaptureSession

private struct QRScannerRepresentable: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

    func makeUIViewController(context: Context) -> QRScannerVC {
        let vc = QRScannerVC()
        vc.coordinator = context.coordinator
        return vc
    }

    func updateUIViewController(_ vc: QRScannerVC, context: Context) {
        // no-op
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let onScan: (String) -> Void
        private var didFire = false

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput metadataObjects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard !didFire else { return }
            guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  obj.type == .qr,
                  let str = obj.stringValue else { return }
            didFire = true
            DispatchQueue.main.async { [weak self] in
                self?.onScan(str)
            }
        }
    }
}

fileprivate final class QRScannerVC: UIViewController {
    weak var coordinator: QRScannerRepresentable.Coordinator?
    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupSession()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.session.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    private func setupSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return
        }
        if session.canAddInput(input) {
            session.addInput(input)
        }
        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
        }
        output.setMetadataObjectsDelegate(coordinator, queue: .main)
        if output.availableMetadataObjectTypes.contains(.qr) {
            output.metadataObjectTypes = [.qr]
        }

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        self.previewLayer = layer
    }
}
