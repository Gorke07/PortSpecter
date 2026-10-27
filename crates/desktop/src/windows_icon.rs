//! Iced sets Winit's small window icon; Windows' large/taskbar icon is separate.
use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}
#[link(name = "user32")]
unsafe extern "system" {
    fn LoadImageW(
        instance: *mut c_void,
        name: *const u16,
        kind: u32,
        width: i32,
        height: i32,
        flags: u32,
    ) -> *mut c_void;
    fn SendMessageW(window: *mut c_void, message: u32, wparam: usize, lparam: isize) -> isize;
}

pub fn set_taskbar_icon(window: &dyn iced::window::Window) {
    use iced::window::raw_window_handle::RawWindowHandle;
    let Ok(handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return;
    };
    // SAFETY: called on the window thread by iced::window::run. Resource 1 is
    // embedded by build.rs. LR_SHARED makes its lifetime belong to the module;
    // it must not be destroyed while Windows retains it for WM_SETICON.
    unsafe {
        let module = GetModuleHandleW(std::ptr::null());
        if module.is_null() {
            return;
        }
        let icon = LoadImageW(module, std::ptr::without_provenance(1), 1, 256, 256, 0x8000);
        if !icon.is_null() {
            SendMessageW(handle.hwnd.get() as *mut c_void, 0x0080, 1, icon as isize);
        }
    }
}
