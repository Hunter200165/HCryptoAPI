unit HCryptoAPI.Cipher.EncryBIT_v12;

{ Deprecated: Do not use this }
{ Contains implementation of HEncryBIT v.12 (insecure) }
{ Can be used, but it is strongly recommended to avoid usage }
{ Can effectively encrypt data at maximum of 256 bytes }

interface

uses
  System.SysUtils,
  HCryptoAPI.Types,
  HCryptoAPI.Assembler,
  HCryptoAPI.Commons;

type
  HCrypto_E_KeyTooSmall = Exception;

type
  HCrypto_HEncryBIT_v12_Cipher = class(TObject)
  public
    class procedure EncryptBuffer(var Bytes: TBytesArray; const Key: TBytesArray); static;
    class procedure DecryptBuffer(var Bytes: TBytesArray; const Key: TBytesArray); static;
end;

const
  HCrypto_HEB_v12_Size_Length = 4;

implementation

{ HCrypto_HEncryBIT_v12_Cipher }

class procedure HCrypto_HEncryBIT_v12_Cipher.DecryptBuffer(var Bytes: TBytesArray; const Key: TBytesArray);
var Len, i, LenD, PosK: Integer;
    Shift: Cardinal;
    Direction: Byte;
    ShiftArray: array[1..HCrypto_HEB_v12_Size_Length] of byte absolute Shift;
    PureKey: TBytesArray;
begin
  Len := Length(Key);
  LenD := Length(Bytes);
  PosK := 0;
  if Len < (HCrypto_HEB_v12_Size_Length + 2) then
    raise HCrypto_E_KeyTooSmall.Create('Key size is too small.');
  Direction := Key[0];
  for i := 1 to HCrypto_HEB_v12_Size_Length do
    ShiftArray[i] := Key[i];
  PureKey := Copy(Key, HCrypto_HEB_v12_Size_Length + 1, Len - (HCrypto_HEB_v12_Size_Length + 1));
  Len := Length(PureKey);
  if not HCrypto_Direction(Direction) then
    HCrypto_ASM_RORREGS(Bytes, Shift)
  else
    HCrypto_ASM_ROLREGS(Bytes, Shift);
  for i := 0 to LenD do begin
    Bytes[i] := Bytes[i] xor PureKey[PosK];
    PosK := (PosK + 1) mod Len;
  end;
end;

class procedure HCrypto_HEncryBIT_v12_Cipher.EncryptBuffer(var Bytes: TBytesArray; const Key: TBytesArray);
var Len, i, LenD, PosK: Integer;
    Shift: Cardinal;
    Direction: Byte;
    ShiftArray: array[1..HCrypto_HEB_v12_Size_Length] of byte absolute Shift;
    PureKey: TBytesArray;
begin
  Len := Length(Key);
  LenD := Length(Bytes);
  PosK := 0;
  if Len < (HCrypto_HEB_v12_Size_Length + 2) then
    raise HCrypto_E_KeyTooSmall.Create('Key size is too small.');
  Direction := Key[0];
  for i := 1 to HCrypto_HEB_v12_Size_Length do
    ShiftArray[i] := Key[i];
  PureKey := Copy(Key, HCrypto_HEB_v12_Size_Length + 1, Len - (HCrypto_HEB_v12_Size_Length + 1));
  Len := Length(PureKey);
  for i := 0 to LenD do begin
    Bytes[i] := Bytes[i] xor PureKey[PosK];
    PosK := (PosK + 1) mod Len;
  end;
  if HCrypto_Direction(Direction) then
    HCrypto_ASM_RORREGS(Bytes, Shift)
  else
    HCrypto_ASM_ROLREGS(Bytes, Shift);
end;

end.
