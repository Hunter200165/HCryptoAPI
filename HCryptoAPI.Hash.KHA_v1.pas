unit HCryptoAPI.Hash.KHA_v1;

{ Implements Key Hashing Algorithm }
{ I'm shocked, but it is very secure. }
{ No need to implement SKHA (Secure Key Hashing Algorithm) }

interface

uses
  HCryptoAPI.Types,
  HCryptoAPI.Commons,
  HCryptoAPI.Cipher.EncryBIT_v12,
  HCryptoAPI.Hash.Raw_v1;

function HCrypto_HKHA_v1_Hash(const Bytes: TBytesArray; Key: TBytesArray; const Size: Integer = 256; const Rounds: Integer = 256): TBytesArray; overload;
function HCrypto_HKHA_v1_Hash(const S: String; const Key: TBytesArray; const Size: Integer = 256; const Rounds: Integer = 256): TBytesArray; overload;
function HCrypto_HKHA_v1_Hash(const S: String; const Key: String; const Size: Integer = 256; const Rounds: Integer = 256): TBytesArray; overload;

implementation

function HCrypto_HKHA_v1_Hash(const Bytes: TBytesArray; Key: TBytesArray; const Size: Integer = 256; const Rounds: Integer = 256): TBytesArray; overload;
var InitialHash, InitialKeyHash: TBytesArray;
    i, k, Pos: Integer;
begin
  InitialHash := HCrypto_HRv1_Hash(Bytes);
  InitialKeyHash := HCrypto_HRv1_Hash(Key);
  Key := HCrypto_HRv1_Hash(InitialKeyHash);
  HCrypto_ReLength(Result, Size);
  Pos := 0;
  for i := 1 to Rounds do begin
    InitialKeyHash := HCrypto_Encrypt(HCrypto_HEncryBIT_v12_Cipher.EncryptBuffer, Key, InitialKeyHash);
    InitialHash := HCrypto_Encrypt(HCrypto_HEncryBIT_v12_Cipher.EncryptBuffer, InitialHash, InitialKeyHash);
    for k := 0 to Length(InitialHash) do begin
      Result[Pos] := Result[Pos] xor InitialHash[k];
      Pos := (Pos + 1) mod Size;
    end;
  end;
end;

function HCrypto_HKHA_v1_Hash(const S: String; const Key: TBytesArray; const Size: Integer = 256; const Rounds: Integer = 256): TBytesArray; overload;
begin
  Result := HCrypto_HKHA_v1_Hash(HCrypto_StringToBytes(S), Key, Size, Rounds);
end;

function HCrypto_HKHA_v1_Hash(const S: String; const Key: String; const Size: Integer = 256; const Rounds: Integer = 256): TBytesArray; overload;
begin
  Result := HCrypto_HKHA_v1_Hash(HCrypto_StringToBytes(S), HCrypto_StringToBytes(Key), Size, Rounds);
end;

end.
