// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authentication.proto

#include "authentication.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

namespace classic {
namespace protocol {
namespace v1 {
namespace authentication {
PROTOBUF_CONSTEXPR AuthSessionResponse::AuthSessionResponse(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_._has_bits_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}
  , /*decltype(_impl_.entitlements_)*/{}
  , /*decltype(_impl_.locale_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.account_id_)*/int64_t{0}
  , /*decltype(_impl_.id_)*/int64_t{0}
  , /*decltype(_impl_.not_valid_after_)*/int64_t{0}
  , /*decltype(_impl_.game_id_)*/int64_t{0}} {}
struct AuthSessionResponseDefaultTypeInternal {
  PROTOBUF_CONSTEXPR AuthSessionResponseDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~AuthSessionResponseDefaultTypeInternal() {}
  union {
    AuthSessionResponse _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 AuthSessionResponseDefaultTypeInternal _AuthSessionResponse_default_instance_;
PROTOBUF_CONSTEXPR OfflineCookie::OfflineCookie(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_._has_bits_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}
  , /*decltype(_impl_.proto_name_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.proto_payload_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.signature_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.game_id_)*/int64_t{0}} {}
struct OfflineCookieDefaultTypeInternal {
  PROTOBUF_CONSTEXPR OfflineCookieDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~OfflineCookieDefaultTypeInternal() {}
  union {
    OfflineCookie _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 OfflineCookieDefaultTypeInternal _OfflineCookie_default_instance_;
PROTOBUF_CONSTEXPR OfflineCookies::OfflineCookies(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.cookie_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct OfflineCookiesDefaultTypeInternal {
  PROTOBUF_CONSTEXPR OfflineCookiesDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~OfflineCookiesDefaultTypeInternal() {}
  union {
    OfflineCookies _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 OfflineCookiesDefaultTypeInternal _OfflineCookies_default_instance_;
}  // namespace authentication
}  // namespace v1
}  // namespace protocol
}  // namespace classic
namespace classic {
namespace protocol {
namespace v1 {
namespace authentication {

// ===================================================================

class AuthSessionResponse::_Internal {
 public:
  using HasBits = decltype(std::declval<AuthSessionResponse>()._impl_._has_bits_);
  static constexpr int32_t kHasBitsOffset =
    8 * PROTOBUF_FIELD_OFFSET(AuthSessionResponse, _impl_._has_bits_);
  static void set_has_account_id(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
  static void set_has_id(HasBits* has_bits) {
    (*has_bits)[0] |= 4u;
  }
  static void set_has_not_valid_after(HasBits* has_bits) {
    (*has_bits)[0] |= 8u;
  }
  static void set_has_game_id(HasBits* has_bits) {
    (*has_bits)[0] |= 16u;
  }
  static void set_has_locale(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static bool MissingRequiredFields(const HasBits& has_bits) {
    return ((has_bits[0] & 0x0000001e) ^ 0x0000001e) != 0;
  }
};

AuthSessionResponse::AuthSessionResponse(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:classic.protocol.v1.authentication.AuthSessionResponse)
}
AuthSessionResponse::AuthSessionResponse(const AuthSessionResponse& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite() {
  AuthSessionResponse* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){from._impl_._has_bits_}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.entitlements_){from._impl_.entitlements_}
    , decltype(_impl_.locale_){}
    , decltype(_impl_.account_id_){}
    , decltype(_impl_.id_){}
    , decltype(_impl_.not_valid_after_){}
    , decltype(_impl_.game_id_){}};

  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  _impl_.locale_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.locale_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_locale()) {
    _this->_impl_.locale_.Set(from._internal_locale(), 
      _this->GetArenaForAllocation());
  }
  ::memcpy(&_impl_.account_id_, &from._impl_.account_id_,
    static_cast<size_t>(reinterpret_cast<char*>(&_impl_.game_id_) -
    reinterpret_cast<char*>(&_impl_.account_id_)) + sizeof(_impl_.game_id_));
  // @@protoc_insertion_point(copy_constructor:classic.protocol.v1.authentication.AuthSessionResponse)
}

inline void AuthSessionResponse::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.entitlements_){arena}
    , decltype(_impl_.locale_){}
    , decltype(_impl_.account_id_){int64_t{0}}
    , decltype(_impl_.id_){int64_t{0}}
    , decltype(_impl_.not_valid_after_){int64_t{0}}
    , decltype(_impl_.game_id_){int64_t{0}}
  };
  _impl_.locale_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.locale_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

AuthSessionResponse::~AuthSessionResponse() {
  // @@protoc_insertion_point(destructor:classic.protocol.v1.authentication.AuthSessionResponse)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<std::string>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void AuthSessionResponse::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.entitlements_.~RepeatedPtrField();
  _impl_.locale_.Destroy();
}

void AuthSessionResponse::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void AuthSessionResponse::Clear() {
// @@protoc_insertion_point(message_clear_start:classic.protocol.v1.authentication.AuthSessionResponse)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.entitlements_.Clear();
  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    _impl_.locale_.ClearNonDefaultToEmpty();
  }
  if (cached_has_bits & 0x0000001eu) {
    ::memset(&_impl_.account_id_, 0, static_cast<size_t>(
        reinterpret_cast<char*>(&_impl_.game_id_) -
        reinterpret_cast<char*>(&_impl_.account_id_)) + sizeof(_impl_.game_id_));
  }
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* AuthSessionResponse::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated string entitlements = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          ptr -= 1;
          do {
            ptr += 1;
            auto str = _internal_add_entitlements();
            ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
        } else
          goto handle_unusual;
        continue;
      // required int64 account_id = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 32)) {
          _Internal::set_has_account_id(&has_bits);
          _impl_.account_id_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // required int64 id = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 40)) {
          _Internal::set_has_id(&has_bits);
          _impl_.id_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // required int64 not_valid_after = 6;
      case 6:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 48)) {
          _Internal::set_has_not_valid_after(&has_bits);
          _impl_.not_valid_after_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // required int64 game_id = 8;
      case 8:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 64)) {
          _Internal::set_has_game_id(&has_bits);
          _impl_.game_id_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // optional string locale = 9;
      case 9:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 74)) {
          auto str = _internal_mutable_locale();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<std::string>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  _impl_._has_bits_.Or(has_bits);
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* AuthSessionResponse::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:classic.protocol.v1.authentication.AuthSessionResponse)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated string entitlements = 1;
  for (int i = 0, n = this->_internal_entitlements_size(); i < n; i++) {
    const auto& s = this->_internal_entitlements(i);
    target = stream->WriteString(1, s, target);
  }

  cached_has_bits = _impl_._has_bits_[0];
  // required int64 account_id = 4;
  if (cached_has_bits & 0x00000002u) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt64ToArray(4, this->_internal_account_id(), target);
  }

  // required int64 id = 5;
  if (cached_has_bits & 0x00000004u) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt64ToArray(5, this->_internal_id(), target);
  }

  // required int64 not_valid_after = 6;
  if (cached_has_bits & 0x00000008u) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt64ToArray(6, this->_internal_not_valid_after(), target);
  }

  // required int64 game_id = 8;
  if (cached_has_bits & 0x00000010u) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt64ToArray(8, this->_internal_game_id(), target);
  }

  // optional string locale = 9;
  if (cached_has_bits & 0x00000001u) {
    target = stream->WriteStringMaybeAliased(
        9, this->_internal_locale(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:classic.protocol.v1.authentication.AuthSessionResponse)
  return target;
}

size_t AuthSessionResponse::RequiredFieldsByteSizeFallback() const {
// @@protoc_insertion_point(required_fields_byte_size_fallback_start:classic.protocol.v1.authentication.AuthSessionResponse)
  size_t total_size = 0;

  if (_internal_has_account_id()) {
    // required int64 account_id = 4;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_account_id());
  }

  if (_internal_has_id()) {
    // required int64 id = 5;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_id());
  }

  if (_internal_has_not_valid_after()) {
    // required int64 not_valid_after = 6;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_not_valid_after());
  }

  if (_internal_has_game_id()) {
    // required int64 game_id = 8;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_game_id());
  }

  return total_size;
}
size_t AuthSessionResponse::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:classic.protocol.v1.authentication.AuthSessionResponse)
  size_t total_size = 0;

  if (((_impl_._has_bits_[0] & 0x0000001e) ^ 0x0000001e) == 0) {  // All required fields are present.
    // required int64 account_id = 4;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_account_id());

    // required int64 id = 5;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_id());

    // required int64 not_valid_after = 6;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_not_valid_after());

    // required int64 game_id = 8;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_game_id());

  } else {
    total_size += RequiredFieldsByteSizeFallback();
  }
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated string entitlements = 1;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(_impl_.entitlements_.size());
  for (int i = 0, n = _impl_.entitlements_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
      _impl_.entitlements_.Get(i));
  }

  // optional string locale = 9;
  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_locale());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::_pbi::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void AuthSessionResponse::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::_pbi::DownCast<const AuthSessionResponse*>(
      &from));
}

void AuthSessionResponse::MergeFrom(const AuthSessionResponse& from) {
  AuthSessionResponse* const _this = this;
  // @@protoc_insertion_point(class_specific_merge_from_start:classic.protocol.v1.authentication.AuthSessionResponse)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  _this->_impl_.entitlements_.MergeFrom(from._impl_.entitlements_);
  cached_has_bits = from._impl_._has_bits_[0];
  if (cached_has_bits & 0x0000001fu) {
    if (cached_has_bits & 0x00000001u) {
      _this->_internal_set_locale(from._internal_locale());
    }
    if (cached_has_bits & 0x00000002u) {
      _this->_impl_.account_id_ = from._impl_.account_id_;
    }
    if (cached_has_bits & 0x00000004u) {
      _this->_impl_.id_ = from._impl_.id_;
    }
    if (cached_has_bits & 0x00000008u) {
      _this->_impl_.not_valid_after_ = from._impl_.not_valid_after_;
    }
    if (cached_has_bits & 0x00000010u) {
      _this->_impl_.game_id_ = from._impl_.game_id_;
    }
    _this->_impl_._has_bits_[0] |= cached_has_bits;
  }
  _this->_internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void AuthSessionResponse::CopyFrom(const AuthSessionResponse& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:classic.protocol.v1.authentication.AuthSessionResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool AuthSessionResponse::IsInitialized() const {
  if (_Internal::MissingRequiredFields(_impl_._has_bits_)) return false;
  return true;
}

void AuthSessionResponse::InternalSwap(AuthSessionResponse* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  _impl_.entitlements_.InternalSwap(&other->_impl_.entitlements_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.locale_, lhs_arena,
      &other->_impl_.locale_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(AuthSessionResponse, _impl_.game_id_)
      + sizeof(AuthSessionResponse::_impl_.game_id_)
      - PROTOBUF_FIELD_OFFSET(AuthSessionResponse, _impl_.account_id_)>(
          reinterpret_cast<char*>(&_impl_.account_id_),
          reinterpret_cast<char*>(&other->_impl_.account_id_));
}

std::string AuthSessionResponse::GetTypeName() const {
  return "classic.protocol.v1.authentication.AuthSessionResponse";
}


// ===================================================================

class OfflineCookie::_Internal {
 public:
  using HasBits = decltype(std::declval<OfflineCookie>()._impl_._has_bits_);
  static constexpr int32_t kHasBitsOffset =
    8 * PROTOBUF_FIELD_OFFSET(OfflineCookie, _impl_._has_bits_);
  static void set_has_proto_name(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static void set_has_proto_payload(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
  static void set_has_signature(HasBits* has_bits) {
    (*has_bits)[0] |= 4u;
  }
  static void set_has_game_id(HasBits* has_bits) {
    (*has_bits)[0] |= 8u;
  }
  static bool MissingRequiredFields(const HasBits& has_bits) {
    return ((has_bits[0] & 0x0000000f) ^ 0x0000000f) != 0;
  }
};

OfflineCookie::OfflineCookie(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:classic.protocol.v1.authentication.OfflineCookie)
}
OfflineCookie::OfflineCookie(const OfflineCookie& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite() {
  OfflineCookie* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){from._impl_._has_bits_}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.proto_name_){}
    , decltype(_impl_.proto_payload_){}
    , decltype(_impl_.signature_){}
    , decltype(_impl_.game_id_){}};

  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  _impl_.proto_name_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.proto_name_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_proto_name()) {
    _this->_impl_.proto_name_.Set(from._internal_proto_name(), 
      _this->GetArenaForAllocation());
  }
  _impl_.proto_payload_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.proto_payload_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_proto_payload()) {
    _this->_impl_.proto_payload_.Set(from._internal_proto_payload(), 
      _this->GetArenaForAllocation());
  }
  _impl_.signature_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.signature_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_signature()) {
    _this->_impl_.signature_.Set(from._internal_signature(), 
      _this->GetArenaForAllocation());
  }
  _this->_impl_.game_id_ = from._impl_.game_id_;
  // @@protoc_insertion_point(copy_constructor:classic.protocol.v1.authentication.OfflineCookie)
}

inline void OfflineCookie::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.proto_name_){}
    , decltype(_impl_.proto_payload_){}
    , decltype(_impl_.signature_){}
    , decltype(_impl_.game_id_){int64_t{0}}
  };
  _impl_.proto_name_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.proto_name_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.proto_payload_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.proto_payload_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.signature_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.signature_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

OfflineCookie::~OfflineCookie() {
  // @@protoc_insertion_point(destructor:classic.protocol.v1.authentication.OfflineCookie)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<std::string>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void OfflineCookie::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.proto_name_.Destroy();
  _impl_.proto_payload_.Destroy();
  _impl_.signature_.Destroy();
}

void OfflineCookie::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void OfflineCookie::Clear() {
// @@protoc_insertion_point(message_clear_start:classic.protocol.v1.authentication.OfflineCookie)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000007u) {
    if (cached_has_bits & 0x00000001u) {
      _impl_.proto_name_.ClearNonDefaultToEmpty();
    }
    if (cached_has_bits & 0x00000002u) {
      _impl_.proto_payload_.ClearNonDefaultToEmpty();
    }
    if (cached_has_bits & 0x00000004u) {
      _impl_.signature_.ClearNonDefaultToEmpty();
    }
  }
  _impl_.game_id_ = int64_t{0};
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* OfflineCookie::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // required string proto_name = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_proto_name();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // required string proto_payload = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_proto_payload();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // required string signature = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 26)) {
          auto str = _internal_mutable_signature();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // required int64 game_id = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 32)) {
          _Internal::set_has_game_id(&has_bits);
          _impl_.game_id_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<std::string>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  _impl_._has_bits_.Or(has_bits);
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* OfflineCookie::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:classic.protocol.v1.authentication.OfflineCookie)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _impl_._has_bits_[0];
  // required string proto_name = 1;
  if (cached_has_bits & 0x00000001u) {
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_proto_name(), target);
  }

  // required string proto_payload = 2;
  if (cached_has_bits & 0x00000002u) {
    target = stream->WriteStringMaybeAliased(
        2, this->_internal_proto_payload(), target);
  }

  // required string signature = 3;
  if (cached_has_bits & 0x00000004u) {
    target = stream->WriteStringMaybeAliased(
        3, this->_internal_signature(), target);
  }

  // required int64 game_id = 4;
  if (cached_has_bits & 0x00000008u) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt64ToArray(4, this->_internal_game_id(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:classic.protocol.v1.authentication.OfflineCookie)
  return target;
}

size_t OfflineCookie::RequiredFieldsByteSizeFallback() const {
// @@protoc_insertion_point(required_fields_byte_size_fallback_start:classic.protocol.v1.authentication.OfflineCookie)
  size_t total_size = 0;

  if (_internal_has_proto_name()) {
    // required string proto_name = 1;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_proto_name());
  }

  if (_internal_has_proto_payload()) {
    // required string proto_payload = 2;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_proto_payload());
  }

  if (_internal_has_signature()) {
    // required string signature = 3;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_signature());
  }

  if (_internal_has_game_id()) {
    // required int64 game_id = 4;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_game_id());
  }

  return total_size;
}
size_t OfflineCookie::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:classic.protocol.v1.authentication.OfflineCookie)
  size_t total_size = 0;

  if (((_impl_._has_bits_[0] & 0x0000000f) ^ 0x0000000f) == 0) {  // All required fields are present.
    // required string proto_name = 1;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_proto_name());

    // required string proto_payload = 2;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_proto_payload());

    // required string signature = 3;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_signature());

    // required int64 game_id = 4;
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_game_id());

  } else {
    total_size += RequiredFieldsByteSizeFallback();
  }
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::_pbi::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void OfflineCookie::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::_pbi::DownCast<const OfflineCookie*>(
      &from));
}

void OfflineCookie::MergeFrom(const OfflineCookie& from) {
  OfflineCookie* const _this = this;
  // @@protoc_insertion_point(class_specific_merge_from_start:classic.protocol.v1.authentication.OfflineCookie)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._impl_._has_bits_[0];
  if (cached_has_bits & 0x0000000fu) {
    if (cached_has_bits & 0x00000001u) {
      _this->_internal_set_proto_name(from._internal_proto_name());
    }
    if (cached_has_bits & 0x00000002u) {
      _this->_internal_set_proto_payload(from._internal_proto_payload());
    }
    if (cached_has_bits & 0x00000004u) {
      _this->_internal_set_signature(from._internal_signature());
    }
    if (cached_has_bits & 0x00000008u) {
      _this->_impl_.game_id_ = from._impl_.game_id_;
    }
    _this->_impl_._has_bits_[0] |= cached_has_bits;
  }
  _this->_internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void OfflineCookie::CopyFrom(const OfflineCookie& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:classic.protocol.v1.authentication.OfflineCookie)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool OfflineCookie::IsInitialized() const {
  if (_Internal::MissingRequiredFields(_impl_._has_bits_)) return false;
  return true;
}

void OfflineCookie::InternalSwap(OfflineCookie* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.proto_name_, lhs_arena,
      &other->_impl_.proto_name_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.proto_payload_, lhs_arena,
      &other->_impl_.proto_payload_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.signature_, lhs_arena,
      &other->_impl_.signature_, rhs_arena
  );
  swap(_impl_.game_id_, other->_impl_.game_id_);
}

std::string OfflineCookie::GetTypeName() const {
  return "classic.protocol.v1.authentication.OfflineCookie";
}


// ===================================================================

class OfflineCookies::_Internal {
 public:
};

OfflineCookies::OfflineCookies(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:classic.protocol.v1.authentication.OfflineCookies)
}
OfflineCookies::OfflineCookies(const OfflineCookies& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite() {
  OfflineCookies* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.cookie_){from._impl_.cookie_}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:classic.protocol.v1.authentication.OfflineCookies)
}

inline void OfflineCookies::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.cookie_){arena}
    , /*decltype(_impl_._cached_size_)*/{}
  };
}

OfflineCookies::~OfflineCookies() {
  // @@protoc_insertion_point(destructor:classic.protocol.v1.authentication.OfflineCookies)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<std::string>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void OfflineCookies::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.cookie_.~RepeatedPtrField();
}

void OfflineCookies::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void OfflineCookies::Clear() {
// @@protoc_insertion_point(message_clear_start:classic.protocol.v1.authentication.OfflineCookies)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.cookie_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* OfflineCookies::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated .classic.protocol.v1.authentication.OfflineCookie cookie = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 42)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_cookie(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<42>(ptr));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<std::string>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* OfflineCookies::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:classic.protocol.v1.authentication.OfflineCookies)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .classic.protocol.v1.authentication.OfflineCookie cookie = 5;
  for (unsigned i = 0,
      n = static_cast<unsigned>(this->_internal_cookie_size()); i < n; i++) {
    const auto& repfield = this->_internal_cookie(i);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
        InternalWriteMessage(5, repfield, repfield.GetCachedSize(), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:classic.protocol.v1.authentication.OfflineCookies)
  return target;
}

size_t OfflineCookies::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:classic.protocol.v1.authentication.OfflineCookies)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .classic.protocol.v1.authentication.OfflineCookie cookie = 5;
  total_size += 1UL * this->_internal_cookie_size();
  for (const auto& msg : this->_impl_.cookie_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::_pbi::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void OfflineCookies::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::_pbi::DownCast<const OfflineCookies*>(
      &from));
}

void OfflineCookies::MergeFrom(const OfflineCookies& from) {
  OfflineCookies* const _this = this;
  // @@protoc_insertion_point(class_specific_merge_from_start:classic.protocol.v1.authentication.OfflineCookies)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  _this->_impl_.cookie_.MergeFrom(from._impl_.cookie_);
  _this->_internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void OfflineCookies::CopyFrom(const OfflineCookies& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:classic.protocol.v1.authentication.OfflineCookies)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool OfflineCookies::IsInitialized() const {
  if (!::PROTOBUF_NAMESPACE_ID::internal::AllAreInitialized(_impl_.cookie_))
    return false;
  return true;
}

void OfflineCookies::InternalSwap(OfflineCookies* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  _impl_.cookie_.InternalSwap(&other->_impl_.cookie_);
}

std::string OfflineCookies::GetTypeName() const {
  return "classic.protocol.v1.authentication.OfflineCookies";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace authentication
}  // namespace v1
}  // namespace protocol
}  // namespace classic
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::classic::protocol::v1::authentication::AuthSessionResponse*
Arena::CreateMaybeMessage< ::classic::protocol::v1::authentication::AuthSessionResponse >(Arena* arena) {
  return Arena::CreateMessageInternal< ::classic::protocol::v1::authentication::AuthSessionResponse >(arena);
}
template<> PROTOBUF_NOINLINE ::classic::protocol::v1::authentication::OfflineCookie*
Arena::CreateMaybeMessage< ::classic::protocol::v1::authentication::OfflineCookie >(Arena* arena) {
  return Arena::CreateMessageInternal< ::classic::protocol::v1::authentication::OfflineCookie >(arena);
}
template<> PROTOBUF_NOINLINE ::classic::protocol::v1::authentication::OfflineCookies*
Arena::CreateMaybeMessage< ::classic::protocol::v1::authentication::OfflineCookies >(Arena* arena) {
  return Arena::CreateMessageInternal< ::classic::protocol::v1::authentication::OfflineCookies >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>