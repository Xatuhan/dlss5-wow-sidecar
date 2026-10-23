#include "capture/WgcSource.h"

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>
#include <d3d11_4.h>
#include <wrl/client.h>

#include <mutex>

#include "gpu/DeviceBridge.h"

using Microsoft::WRL::ComPtr;
namespace wgc = winrt::Windows::Graphics::Capture;
namespace wgdx = winrt::Windows::Graphics::DirectX;

namespace sidecar {

struct WgcSource::Impl {
  wgc::GraphicsCaptureItem item{nullptr};
  wgc::Direct3D11CaptureFramePool pool{nullptr};
  wgc::GraphicsCaptureSession session{nullptr};
  winrt::event_token frameToken{};
  winrt::event_token closedToken{};
  DeviceBridge* bridge = nullptr;
  WgcSource::DropCallback onDrop;
  WgcSource* owner = nullptr;

  // Frames arrive on a pool thread. Revoking the handler stops new deliveries
  // but does not wait for one already running, so without this a frame landing
  // during Stop() could touch the bridge and the owner after both were gone.
  // The handler holds the mutex for its whole body and checks `stopped` first;
  // Stop() takes the same mutex to set it, so once Stop() has it no handler is
  // mid-flight and none that starts later will do anything.
  std::mutex mutex;
  bool stopped = false;
};

namespace {

wgdx::Direct3D11::IDirect3DDevice WrapDevice(ID3D11Device* dev) {
  ComPtr<IDXGIDevice> dxgi;
  if (FAILED(dev->QueryInterface(IID_PPV_ARGS(&dxgi)))) return nullptr;
  winrt::com_ptr<::IInspectable> inspectable;
  if (FAILED(CreateDirect3D11DeviceFromDXGIDevice(dxgi.Get(), inspectable.put()))) return nullptr;
  return inspectable.as<wgdx::Direct3D11::IDirect3DDevice>();
}

ComPtr<ID3D11Texture2D> SurfaceToTexture(
    const wgdx::Direct3D11::IDirect3DSurface& surface) {
  auto access = surface.as<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
  ComPtr<ID3D11Texture2D> tex;
  access->GetInterface(IID_PPV_ARGS(&tex));
  return tex;
}

}  // namespace

std::unique_ptr<WgcSource> WgcSource::CreateForWindow(HWND target,
                                                      DeviceBridge& bridge,
                                                      DropCallback onDrop) {
  if (!wgc::GraphicsCaptureSession::IsSupported()) return nullptr;

  auto interop = winrt::get_activation_factory<wgc::GraphicsCaptureItem>()
                     .as<IGraphicsCaptureItemInterop>();
  wgc::GraphicsCaptureItem item{nullptr};
  if (FAILED(interop->CreateForWindow(
          target, winrt::guid_of<wgc::GraphicsCaptureItem>(), winrt::put_abi(item)))) {
    return nullptr;
  }

  auto device = WrapDevice(bridge.D3d11());
  if (!device) return nullptr;

  std::unique_ptr<WgcSource> s(new WgcSource());
  s->target_ = target;
  s->impl_ = std::make_shared<Impl>();
  s->impl_->owner = s.get();
  s->impl_->bridge = &bridge;
  s->impl_->onDrop = std::move(onDrop);
  s->impl_->item = item;

  // Free-threaded so frames arrive on a pool thread rather than needing a
  // message loop on the capture thread.
  s->impl_->pool = wgc::Direct3D11CaptureFramePool::CreateFreeThreaded(
      device, wgdx::DirectXPixelFormat::B8G8R8A8UIntNormalized,
      static_cast<int32_t>(DeviceBridge::kRingDepth), item.Size());

  Impl* impl = s->impl_.get();
  // Weak, so the handler neither keeps Impl alive past its owner nor forms a
  // cycle through the pool that holds it.
  const std::weak_ptr<Impl> weak = s->impl_;
  impl->frameToken = impl->pool.FrameArrived(
      [weak](const wgc::Direct3D11CaptureFramePool& pool, auto&&) {
        const auto self = weak.lock();
        if (!self) return;
        std::lock_guard<std::mutex> lock(self->mutex);
        if (self->stopped) return;
        auto frame = pool.TryGetNextFrame();
        if (!frame) return;
        auto tex = SurfaceToTexture(frame.Surface());
        if (!tex) return;
        const bool dropped = self->bridge->Publish(tex.Get());
        self->owner->delivered_.fetch_add(1, std::memory_order_relaxed);
        if (dropped && self->onDrop) self->onDrop();
      });

  impl->closedToken = item.Closed([weak](auto&&, auto&&) {
    const auto self = weak.lock();
    if (!self) return;
    std::lock_guard<std::mutex> lock(self->mutex);
    if (self->stopped) return;
    self->owner->closed_.store(true, std::memory_order_release);
  });

  s->impl_->session = s->impl_->pool.CreateCaptureSession(item);
  s->impl_->session.IsCursorCaptureEnabled(false);   // WoW draws its own cursor
  s->impl_->session.IsBorderRequired(false);         // no yellow capture border
  return s;
}

WgcSource::~WgcSource() { Stop(); }

bool WgcSource::IsClosed() const {
  if (closed_.load(std::memory_order_acquire)) return true;
  // WGC raises Closed when a window is destroyed normally, but not when the
  // owning process is terminated -- the frames simply stop. Ask the window
  // manager directly rather than waiting for an event that will not arrive.
  return target_ != nullptr && !IsWindow(target_);
}

void WgcSource::Start() {
  if (impl_ && impl_->session) impl_->session.StartCapture();
}

void WgcSource::Stop() {
  if (!impl_) return;
  // First, and released before anything below: closing the session may wait
  // for a handler, and a handler waits for this mutex.
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->stopped = true;
  }
  if (impl_->pool && impl_->frameToken) {
    impl_->pool.FrameArrived(impl_->frameToken);
    impl_->frameToken = {};
  }
  if (impl_->item && impl_->closedToken) {
    impl_->item.Closed(impl_->closedToken);
    impl_->closedToken = {};
  }
  if (impl_->session) { impl_->session.Close(); impl_->session = nullptr; }
  if (impl_->pool) { impl_->pool.Close(); impl_->pool = nullptr; }
}

}  // namespace sidecar
