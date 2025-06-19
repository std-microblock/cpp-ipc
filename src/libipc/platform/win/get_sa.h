#pragma once
#include <aclapi.h>
#include <memoryapi.h>
#include <sddl.h>
#include <vector>
#include <windows.h>
#include <winnt.h>

namespace ipc {
namespace detail {

class SidHolder {
public:
  SidHolder() : sid_buffer_() {}
  ~SidHolder() = default;

  bool CreateEveryone() {
    DWORD sid_size = 0;

    CreateWellKnownSid(WinWorldSid, nullptr, nullptr, &sid_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return false;
    }

    sid_buffer_.resize(sid_size);
    if (!CreateWellKnownSid(WinWorldSid, nullptr, Get(), &sid_size)) {
      return false;
    }
    return true;
  }

  bool CreateUntrusted() {
    SID_IDENTIFIER_AUTHORITY mandatory_label_authority =
        SECURITY_MANDATORY_LABEL_AUTHORITY;

    DWORD sid_size = GetSidLengthRequired(1);
    sid_buffer_.resize(sid_size);

    if (!InitializeSid(Get(), &mandatory_label_authority, 1)) {
      return false;
    }
    *(GetSidSubAuthority(Get(), 0)) = SECURITY_MANDATORY_UNTRUSTED_RID;
    return true;
  }

  PSID Get() {
    return sid_buffer_.empty() ? nullptr
                               : reinterpret_cast<PSID>(sid_buffer_.data());
  }

  DWORD GetLength() const { return static_cast<DWORD>(sid_buffer_.size()); }

private:
  std::vector<BYTE> sid_buffer_;

  SidHolder(const SidHolder &);
  SidHolder &operator=(const SidHolder &);
};

inline LPSECURITY_ATTRIBUTES get_sa() {
  static struct initiator {
    SECURITY_ATTRIBUTES sa_;
    std::vector<BYTE> sd_buffer_;
    bool succ_ = false;

    initiator() {
      SidHolder everyone_sid;
      if (!everyone_sid.CreateEveryone()) {
        return;
      }

      SidHolder untrusted_il_sid;
      if (!untrusted_il_sid.CreateUntrusted()) {
        return;
      }

      DWORD dacl_size =
          sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + everyone_sid.GetLength();
      std::vector<BYTE> dacl_buffer(dacl_size);
      PACL dacl = reinterpret_cast<PACL>(dacl_buffer.data());

      if (!InitializeAcl(dacl, dacl_size, ACL_REVISION))
        return;
      if (!AddAccessAllowedAce(dacl, ACL_REVISION,
                               SYNCHRONIZE | SEMAPHORE_ALL_ACCESS |
                                   EVENT_ALL_ACCESS | FILE_MAP_ALL_ACCESS,
                               everyone_sid.Get()))
        return;

      DWORD sacl_size = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
                        untrusted_il_sid.GetLength();
      std::vector<BYTE> sacl_buffer(sacl_size);
      PACL sacl = reinterpret_cast<PACL>(sacl_buffer.data());

      if (!InitializeAcl(sacl, sacl_size, ACL_REVISION))
        return;
      if (!AddMandatoryAce(sacl, ACL_REVISION, 0,
                           SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                           untrusted_il_sid.Get()))
        return;

      SECURITY_DESCRIPTOR sd_absolute = {0};
      if (!InitializeSecurityDescriptor(&sd_absolute,
                                        SECURITY_DESCRIPTOR_REVISION))
        return;
      if (!SetSecurityDescriptorDacl(&sd_absolute, TRUE, dacl, FALSE))
        return;
      if (!SetSecurityDescriptorSacl(&sd_absolute, TRUE, sacl, FALSE))
        return;

      DWORD sd_buffer_size = 0;
      MakeSelfRelativeSD(&sd_absolute, nullptr, &sd_buffer_size);
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return;

      sd_buffer_.resize(sd_buffer_size);
      PSECURITY_DESCRIPTOR sd_relative =
          reinterpret_cast<PSECURITY_DESCRIPTOR>(sd_buffer_.data());

      if (!MakeSelfRelativeSD(&sd_absolute, sd_relative, &sd_buffer_size))
        return;

      sa_.nLength = sizeof(sa_);
      sa_.lpSecurityDescriptor = sd_relative;
      sa_.bInheritHandle = FALSE;
      succ_ = true;
    }
  } handle;

  return handle.succ_ ? &handle.sa_ : nullptr;
}

} // namespace detail
} // namespace ipc
