unit HCryptoAPI.Cipher.LEncryBIT_v2;

interface

{ Implementation of LowEncryBIT - Fast, Flexible and Secure Stream Cipher (FFSSC) }

uses
  System.Classes,
  HCryptoAPI.Types,
  HCryptoAPI.Assembler,
  HCryptoAPI.Hash.KHA_v1,
  HCryptoAPI.Hash.Raw_v1;

{ This is class instance }

const
  HCrypto_LEncryBITv2_NEExternalKey = 127;
  HCrypto_LEncryBITv2_NEMiddleKey = 65;
  HCrypto_LEncryBITv2_NELowKey = 63;
  HCrypto_LEncryBITv2_EExternalKey = HCrypto_LEncryBITv2_NEExternalKey * HCrypto_LEncryBITv2_NEExternalKey;
  HCrypto_LEncryBITv2_EMiddleKey = HCrypto_LEncryBITv2_NEMiddleKey * HCrypto_LEncryBITv2_NEMiddleKey;
  HCrypto_LEncryBITv2_ELowKey = HCrypto_LEncryBITv2_NELowKey * HCrypto_LEncryBITv2_NELowKey;
  HCrypto_LEncryBITv2_BlockSize = 1048576;

type
  HCrypto_TLEncryBITv2 = class(TObject)
  private
    FPosition: Int64;
    FExternalKey: TBytesArray;
    FMiddleKey: TBytesArray;
    FLowKey: TBytesArray;
    FExternalKeyLength: Int64;
    FMiddleKeyLength: Int64;
    FLowKeyLength: Int64;
    FExternalKeyPosition: Integer;
    FMiddleKeyPosition: Integer;
    FLowKeyPosition: Integer;
    FBytesEncrypted: Int64;
    procedure SetPosition(const Value: Int64); inline;
  protected
    property ExternalKeyPosition: Integer read FExternalKeyPosition write FExternalKeyPosition;
    property MiddleKeyPosition: Integer read FMiddleKeyPosition write FMiddleKeyPosition;
    property LowKeyPosition: Integer read FLowKeyPosition write FLowKeyPosition;
  public
    property Position: Int64 read FPosition write SetPosition;
    property BytesEncrypted: Int64 read FBytesEncrypted;

    { Round keys }
    property ExternalKey: TBytesArray read FExternalKey write FExternalKey;
    property MiddleKey: TBytesArray read FMiddleKey write FMiddleKey;
    property LowKey: TBytesArray read FLowKey write FLowKey;

    property ExternalKeyLength: Int64 read FExternalKeyLength;
    property MiddleKeyLength: Int64 read FMiddleKeyLength;
    property LowKeyLength: Int64 read FLowKeyLength;

    function EncryptByte(const AIn: Byte): Byte; inline;
    function DecryptByte(const EIn: Byte): Byte; inline;
    procedure EncryptBuffer(var Buffer: TBytesArray); inline;
    procedure DecryptBuffer(var Buffer: TBytesArray); inline;
    procedure EncryptStream(StrIn, StrOut: TStream); inline;
    procedure DecryptStream(StrIn, StrOut: TStream); inline;

    procedure ResetMachine;
    procedure SetupKeys;
    procedure NextRound; inline;
    procedure AddStep; inline;
    procedure CreateKeysOutOfPassword(const Password: TBytesArray; const Key: TBytesArray); overload;
    procedure CreateKeysOutOfPassword(const Password: TBytesArray); overload;
    procedure ExpandKeys;

    function GetStrength: Int64;
  end;

implementation

{ HCrypto_TLEncryBit_v2 }

procedure HCrypto_TLEncryBITv2.CreateKeysOutOfPassword(const Password, Key: TBytesArray);
var Buffer: TBytesArray;
begin
  Buffer := HCrypto_HKHA_v1_Hash(Password, Key, 256, 256); { Secure! }
  ExternalKey := Copy(Buffer, 0, HCrypto_LEncryBITv2_NEExternalKey);
  MiddleKey := Copy(Buffer, HCrypto_LEncryBITv2_NEExternalKey, HCrypto_LEncryBITv2_NEMiddleKey);
  LowKey := Copy(Buffer, HCrypto_LEncryBITv2_NEExternalKey + HCrypto_LEncryBITv2_NEMiddleKey, HCrypto_LEncryBITv2_NELowKey);
  SetupKeys;
end;

procedure HCrypto_TLEncryBITv2.AddStep;
begin
  Inc(FLowKeyPosition);
  if LowKeyPosition >= LowKeyLength then begin
    LowKeyPosition := LowKeyPosition - LowKeyLength;
    Inc(FMiddleKeyPosition);
    if MiddleKeyPosition >= MiddleKeyLength then begin
      MiddleKeyPosition := MiddleKeyPosition - MiddleKeyLength;
      Inc(FExternalKeyLength);
      if ExternalKeyPosition >= ExternalKeyLength then
        ExternalKeyPosition := ExternalKeyPosition - ExternalKeyLength;
    end;
  end;
end;

procedure HCrypto_TLEncryBITv2.CreateKeysOutOfPassword(const Password: TBytesArray);
begin
  CreateKeysOutOfPassword(Password, HCrypto_HRv1_Hash(Password));
end;

procedure HCrypto_TLEncryBITv2.DecryptBuffer(var Buffer: TBytesArray);
var i: Integer;
begin
  for i := 0 to Buffer.Size - 1 do begin
    Buffer[i] := DecryptByte(Buffer[i]);
  end;
end;

function HCrypto_TLEncryBITv2.DecryptByte(const EIn: Byte): Byte;
var E, A, K, KEx, AEx, DecTwo, DecThree: Byte;
begin
  K := ExternalKey[ExternalKeyPosition];
  A := MiddleKey[MiddleKeyPosition];
  E := LowKey[LowKeyPosition];
  KEx := K xor E;
  AEx := A xor E;

  DecTwo := EIn;
  { New version }

  HCrypto_ASM_ROLBYTE(DecTwo, (K xor A xor E) mod 8);
  DecTwo := DecTwo xor E;
  DecTwo := Byte(DecTwo - KEx);
  DecTwo := DecTwo xor AEx;
  DecTwo := Byte(DecTwo - E);

  { Old version }
  HCrypto_ASM_ROLBYTE(DecTwo, E mod 8);
  DecThree := Byte(DecTwo - AEx);
  Result := DecThree xor KEx;

  NextRound;
end;

procedure HCrypto_TLEncryBITv2.DecryptStream(StrIn, StrOut: TStream);
var Buffer: TBytesArray;
    i, Chunks, Remain, Count: Int64;
begin
  Count := StrIn.Size - StrIn.Position;
  Chunks := Count div HCrypto_LEncryBITv2_BlockSize;
  Remain := Count mod HCrypto_LEncryBITv2_BlockSize;
  Buffer.Size := HCrypto_LEncryBITv2_BlockSize;
  for i := 1 to Chunks do begin
    StrIn.ReadBuffer(Buffer[0], HCrypto_LEncryBITv2_BlockSize);
    DecryptBuffer(Buffer);
    StrOut.WriteBuffer(Buffer[0], HCrypto_LEncryBITv2_BlockSize);
  end;
  if Remain > 0 then begin
    StrIn.ReadBuffer(Buffer[0], Remain);
    DecryptBuffer(Buffer);
    StrOut.WriteBuffer(Buffer[0], Remain);
  end;
end;

procedure HCrypto_TLEncryBITv2.EncryptBuffer(var Buffer: TBytesArray);
var i: Integer;
begin
  for i := 0 to Buffer.Size - 1 do begin
    Buffer[i] := EncryptByte(Buffer[i]);
  end;
end;

function HCrypto_TLEncryBITv2.EncryptByte(const AIn: Byte): Byte;
var E, A, K, KEx, AEx, EncTwo, EncThree: Byte;
begin
  K := ExternalKey[ExternalKeyPosition];
  A := MiddleKey[MiddleKeyPosition];
  E := LowKey[LowKeyPosition];
  KEx := K xor E;
  AEx := A xor E;

  EncTwo := AIn xor KEx;
  EncThree := (EncTwo + AEx) mod 256;
  HCrypto_ASM_RORBYTE(EncThree, E mod 8);

  { Spinning low wheel by 1 }
  NextRound;
  { New version }
  Result := (EncThree + E) mod 256;
  Result := Result xor AEx;
  Result := (Result + KEx) mod 256;
  Result := Result xor E;
  HCrypto_ASM_RORBYTE(Result, (K xor A xor E) mod 8);
end;

procedure HCrypto_TLEncryBITv2.EncryptStream(StrIn, StrOut: TStream);
var Buffer: TBytesArray;
    i, Chunks, Remain, Count: Int64;
begin
  Count := StrIn.Size - StrIn.Position;
  Chunks := Count div HCrypto_LEncryBITv2_BlockSize;
  Remain := Count mod HCrypto_LEncryBITv2_BlockSize;
  Buffer.Size := HCrypto_LEncryBITv2_BlockSize;
  for i := 1 to Chunks do begin
    StrIn.ReadBuffer(Buffer[0], HCrypto_LEncryBITv2_BlockSize);
    EncryptBuffer(Buffer);
    StrOut.WriteBuffer(Buffer[0], HCrypto_LEncryBITv2_BlockSize);
  end;
  if Remain > 0 then begin
    StrIn.ReadBuffer(Buffer[0], Remain);
    EncryptBuffer(Buffer);
    StrOut.WriteBuffer(Buffer[0], Remain);
  end;
end;

procedure HCrypto_TLEncryBITv2.ExpandKeys;
var Buffer: TBytesArray;
    Count, i: Int64;
begin
  Count := HCrypto_LEncryBITv2_EExternalKey + HCrypto_LEncryBITv2_EMiddleKey + HCrypto_LEncryBITv2_ELowKey;
  Buffer.Size := Count;
  Position := 0;
  for i := 0 to Count - 1 do begin
    Buffer[i] := EncryptByte(i mod 256);
  end;
  ExternalKey := Copy(Buffer, 0, HCrypto_LEncryBITv2_EExternalKey);
  MiddleKey := Copy(Buffer, HCrypto_LEncryBITv2_EExternalKey, HCrypto_LEncryBITv2_EMiddleKey);
  LowKey := Copy(Buffer, HCrypto_LEncryBITv2_EExternalKey + HCrypto_LEncryBITv2_EMiddleKey, HCrypto_LEncryBITv2_ELowKey);
  SetupKeys;
end;

function HCrypto_TLEncryBITv2.GetStrength: Int64;
begin
  Result := Int64(ExternalKey.Size) * Int64 (MiddleKey.Size) * Int64 (LowKey.Size);
end;

procedure HCrypto_TLEncryBITv2.NextRound;
begin
//  FPosition := FPosition + 1;
//  LowKeyPosition := (FPosition mod LowKeyLength);
//  MiddleKeyPosition := (((FPosition div LowKeyLength)) mod MiddleKeyLength);
//  ExternalKeyPosition := ((((FPosition div LowKeyLength) div MiddleKeyLength)) mod ExternalKeyLength);
  AddStep;
  FBytesEncrypted := FBytesEncrypted + 1;
end;

procedure HCrypto_TLEncryBITv2.ResetMachine;
begin
  SetupKeys;
  FBytesEncrypted := 0;
end;

procedure HCrypto_TLEncryBITv2.SetPosition(const Value: Int64);
var Val: Int64;
begin
  FPosition := Value;
  LowKeyPosition := Value mod LowKeyLength;
  Val := Value div LowKeyLength;
  MiddleKeyPosition := Val mod MiddleKeyLength;
  Val := Val div MiddleKeyLength;
  ExternalKeyPosition := Val mod ExternalKeyLength;
end;

procedure HCrypto_TLEncryBITv2.SetupKeys;
begin
  FExternalKeyLength := ExternalKey.Size;
  FMiddleKeyLength := MiddleKey.Size;
  FLowKeyLength := MiddleKey.Size;
  Position := 0;
end;

end.
