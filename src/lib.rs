use std::{cell, ffi, mem, ptr};

use windows::{
    core::{GUID, HRESULT},
    Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_POINTER, S_OK},
};

use std::cell::RefCell;

use windows::{
    core::implement,
    Win32::UI::Shell::{ICredentialProvider, ICredentialProvider_Impl},
};
use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOINTERFACE, E_NOTIMPL, S_FALSE};

#[implement(ICredentialProvider)]
struct Provider {
    _mutable_state: cell::RefCell<u32>,
}

impl Provider {
    fn new() -> Self {
        Self {
            _mutable_state: cell::RefCell::new(0),
        }
    }
}

impl ICredentialProvider_Impl for Provider {
    fn SetUsageScenario(
        &self,
        _cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    // ...
}

#[implement(IClassFactory)]
struct ProviderFactory;

impl IClassFactory_Impl for ProviderFactory {
    fn CreateInstance(
        &self,
        punkouter: &core::option::Option<windows::core::IUnknown>,
        riid: *const windows::core::GUID,
        ppvobject: *mut *mut core::ffi::c_void,
    ) -> windows::core::Result<()> {
        // Validate arguments
        if ppvobject.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *ppvobject = ptr::null_mut() };
        if riid.is_null() {
            return Err(E_INVALIDARG.into());
        }
        let riid = unsafe { *riid };
        if punkouter.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        // We're only handling requests for `IID_ICredentialProvider`
        if riid != ICredentialProvider::IID {
            return Err(E_NOINTERFACE.into());
        }

        // Construct credential provider and return it as an `ICredentialProvider`
        // interface
        let provider: ICredentialProvider = Provider::new().into();
        unsafe { *ppvobject = mem::transmute(provider) };
        Ok(())
    }

    fn LockServer(&self, _flock: windows::Win32::Foundation::BOOL) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
}

#[no_mangle]
#[no_mangle]
extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut ffi::c_void,
) -> HRESULT {
    // The "class ID" this credential provider is identified by. This value needs to
    // match the value used when registering the credential provider (see the .reg
    // script above)
    const CLSID_CP_DEMO: GUID = GUID::from_u128(0xDED30376_B312_4168_B2D3_2D0B3EADE513);

    // Validate arguments
    if ppv.is_null() {
        return E_POINTER;
    }
    unsafe { *ppv = ptr::null_mut() };
    if rclsid.is_null() || riid.is_null() {
        return E_INVALIDARG;
    }

    let rclsid = unsafe { *rclsid };
    let riid = unsafe { *riid };
    // The following isn't strictly correct; a client *could* request an interface other
    // than `IClassFactory::IID`, which this implementation is simply failing.
    // This is safe, even if overly restrictive
    if rclsid != CLSID_CP_DEMO || riid != IClassFactory::IID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    // Construct the factory object and return its `IClassFactory` interface
    let factory: IClassFactory = ProviderFactory.into();
    unsafe { *ppv = mem::transmute(factory) };
    S_OK
}

#[no_mangle]
extern "system" fn DllCanUnloadNow() -> HRESULT {
    // Since we aren't tracking module references (yet), it's never safe to unload this
    // module
    S_FALSE
}