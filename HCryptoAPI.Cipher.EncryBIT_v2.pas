unit HCryptoAPI.Cipher.EncryBIT_v2;

interface

uses
  HCryptoAPI.Equalizer,
  HCryptoAPI.Types,
  HCryptoAPI.Commons,
  HCryptoAPI.Blocker,
  HCryptoAPI.Random;

type
  HCrypto_EncryBITv2_PackedShift = record
  private
    FShift: TBytesArray;
    FDirection: Boolean;
    function GetSize: Integer;
    procedure SetSize(const Value: Integer);
    function GetValue: Int64;
  public
    property Size: Integer read GetSize write SetSize;
    property Direction: Boolean read FDirection write FDirection;
    property Shift: TBytesArray read FShift write FShift;
    property Value: Int64 read GetValue;
  end;
  HCrypto_EncryBITv2_PackedShift_Array = array of HCrypto_EncryBITv2_PackedShift;
  HCrypto_EncryBITv2_ExpandedKey = record
  private
    FEncryptionKey: TBytesArray;
    FOverallShift: Int64;
    FBlockSize: Integer;
  public
    property EncryptionKey: TBytesArray read FEncryptionKey write FEncryptionKey;
    property OverallShift: Int64 read FOverallShift write FOverallShift;
    property BlockSize: Integer read FBlockSize write FBlockSize;
  end;
  
  HCrypto_EncryBITv2_Key = record
  private
    FPackedShifts: HCrypto_EncryBITv2_PackedShift_Array;
    FShiftSize: Integer;
    FEncryptionKey: TBytesArray;
    FRounds: Cardinal;
    FBlockSizeBits: Integer;
    function GetShiftArraySize: Integer;
    procedure SetShiftArraySize(const Value: Integer);
    procedure ReassignShiftSize(const Size: Integer);
  public
    property ShiftArraySize: Integer read GetShiftArraySize write SetShiftArraySize;
    property PackedShifts: HCrypto_EncryBITv2_PackedShift_Array read FPackedShifts write FPackedShifts;
    property ShiftSize: Integer read FShiftSize write ReassignShiftSize;
    property EncryptionKey: TBytesArray read FEncryptionKey write FEncryptionKey;
    property Rounds: Cardinal read FRounds write FRounds;
    property BlockSizeBits: Integer read FBlockSizeBits write FBlockSizeBits;
    procedure AllocateKey(const Rounds: Cardinal = 256; const BlockBits: Integer = 256);
    procedure FillPseudoRandom;
    function ExpandKey: HCrypto_EncryBITv2_ExpandedKey;
    class function Create(const BlockSizeBits: Integer = 256; const Rounds: Cardinal = 256): HCrypto_EncryBITv2_Key; static;
  end;

  HCrypto_HEncryBITv2_Cipher = class(TObject) 
  public 
    (* Not expanded key [very slow, but reliable] *)
    { Encryption }
    class procedure Encrypt_NExpanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_Key); static;
    class procedure EncryptBlock_NExpanded(var Block: TBytesArray; Key: HCrypto_EncryBITv2_Key); static;
    { Decryption }
    class procedure Decrypt_NExpanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_Key); static;
    class procedure DecryptBlock_NExpanded(var Block: TBytesArray; Key: HCrypto_EncryBITv2_Key); static; 
    (* Expanded [Significantly faster!] *)
    { Encryption }
    class procedure Encrypt_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey); static;
    class procedure EncryptBlock_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey); static;
    { Decryption }
    class procedure Decrypt_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey); static;
    class procedure DecryptBlock_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey); static;
  end;

implementation

{ HCrypto_EncryBITv2_PackedShift }

function HCrypto_EncryBITv2_PackedShift.GetSize: Integer;
begin
  Result := Length(Shift);
end;

function HCrypto_EncryBITv2_PackedShift.GetValue: Int64;
begin
  Result := HCrypto_TEqualizer<Int64>.FromBytes(FShift);
end;

procedure HCrypto_EncryBITv2_PackedShift.SetSize(const Value: Integer);
begin
  SetLength(FShift, Value);
end;

{ HCrypto_EncryBITv2_Key }

procedure HCrypto_EncryBITv2_Key.AllocateKey(const Rounds: Cardinal; const BlockBits: Integer);
var Move, BytesSize: Integer;
begin
  ShiftArraySize := Rounds;
  Move := BlockBits * 2;
  BytesSize := HCrypto_GetNumberByteSize(Move);
  ReassignShiftSize(BytesSize);
end;

class function HCrypto_EncryBITv2_Key.Create(const BlockSizeBits: Integer; const Rounds: Cardinal): HCrypto_EncryBITv2_Key;
begin
  Result.BlockSizeBits := BlockSizeBits;
  Result.Rounds := Rounds;
  Result.AllocateKey(Rounds, BlockSizeBits);
end;

function HCrypto_EncryBITv2_Key.ExpandKey: HCrypto_EncryBITv2_ExpandedKey;
var i: Integer;
    Overall, BytesC: Int64;
    Key, Buffer: TBytesArray;
begin
  Overall := 0;
  for i := 0 to ShiftArraySize - 1 do begin
    { Overall }
    Overall := Overall + HCrypto_DirectionToNumber(PackedShifts[i].Value, PackedShifts[i].Direction);
  end;
  Result.OverallShift := Overall;
  BytesC := BlockSizeBits div 8;
  HCrypto_ReLength(Key, BytesC);
  for i := 0 to ShiftArraySize - 1 do begin 
    Buffer := HCrypto_CopyBytes(EncryptionKey);
    HCrypto_RORBits(Buffer, Overall);
    Key := HCrypto_XorBuffer(Key, Buffer);
    Overall := Overall - HCrypto_DirectionToNumber(PackedShifts[i].Value, PackedShifts[i].Direction);
  end;
  Assert(Overall = 0, 'Overall is not equal to zero. It is critical error.');
  Result.EncryptionKey := Key;
  Result.BlockSize := BlockSizeBits;
end;

procedure HCrypto_EncryBITv2_Key.FillPseudoRandom;
var i: Integer;
begin
  for I := 0 to ShiftArraySize - 1 do begin 
    PackedShifts[i].Shift := HCrypto_PseudoRandomBuffer(PackedShifts[i].GetSize);
    PackedShifts[i].Direction := HCrypto_PseudoRandomBoolean;
  end;
  EncryptionKey := HCrypto_PseudoRandomBuffer(BlockSizeBits div 8);
end;

function HCrypto_EncryBITv2_Key.GetShiftArraySize: Integer;
begin
  Result := Length(PackedShifts);
end;

procedure HCrypto_EncryBITv2_Key.ReassignShiftSize(const Size: Integer);
var i: Integer;
begin
  for i := 0 to ShiftArraySize - 1 do begin
    PackedShifts[i].Size := Size;
  end;
  FShiftSize := Size;
end;

procedure HCrypto_EncryBITv2_Key.SetShiftArraySize(const Value: Integer);
begin
  SetLength(FPackedShifts, Value);
end;

{ HCrypto_HEncryBITv2_Cipher }

class procedure HCrypto_HEncryBITv2_Cipher.DecryptBlock_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey);
begin
  HCrypto_XorBufferFastLimited(Bytes, Key.EncryptionKey);
  HCrypto_ROLBits(Bytes, Key.OverallShift);
end;

class procedure HCrypto_HEncryBITv2_Cipher.DecryptBlock_NExpanded(var Block: TBytesArray; Key: HCrypto_EncryBITv2_Key);
var i: Integer;
begin
  for i := Key.Rounds - 1 downto 0 do begin 
    HCrypto_ROLBits(Block, HCrypto_DirectionToNumber(Key.PackedShifts[i].GetValue, Key.PackedShifts[i].Direction));
    HCrypto_XorBufferFastLimited(Block, Key.EncryptionKey);
  end;
end;

class procedure HCrypto_HEncryBITv2_Cipher.Decrypt_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey);
var Offset, Blocks, Remain, Len, BytesC, i, k, Size: Int64;
    Buffer, LenArr: TBytesArray;
begin
  SetLength(LenArr, 8);
  for i := 0 to Length(LenArr) - 1 do
    LenArr[i] := Bytes[Length(Bytes) - Length(LenArr) + i];
  Size := HCrypto_TEqualizer<Int64>.FromBytes(LenArr);
  SetLength(Bytes, Length(Bytes) - Length(LenArr));
  
  Offset := 0;
  BytesC := Key.BlockSize div 8;
  Len := Length(Bytes);
  Blocks := Len div BytesC;
  Remain := Len mod BytesC;
  for i := 1 to Blocks do begin
    Buffer := Copy(Bytes, (i - 1) * BytesC, BytesC);
    HCrypto_HEncryBITv2_Cipher.DecryptBlock_Expanded(Buffer, Key);
    for k := 0 to BytesC - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
    Offset := Offset + BytesC;
  end;
  if Remain > 0 then begin
    Buffer := Copy(Bytes, Blocks * BytesC, Remain);
    HCrypto_HEncryBITv2_Cipher.DecryptBlock_Expanded(Buffer, Key);
    for k := 0 to Remain - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
  end;

  SetLength(Bytes, Size);
  { All done. }
end;

class procedure HCrypto_HEncryBITv2_Cipher.Decrypt_NExpanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_Key);
var Offset, Blocks, Remain, Len, BytesC, i, k, Size: Int64;
    Buffer, LenArr: TBytesArray;
begin
  SetLength(LenArr, 8);
  for i := 0 to Length(LenArr) - 1 do
    LenArr[i] := Bytes[Length(Bytes) - Length(LenArr) + i];
  Size := HCrypto_TEqualizer<Int64>.FromBytes(LenArr);
  SetLength(Bytes, Length(Bytes) - Length(LenArr));
  
  Offset := 0;
  BytesC := Key.BlockSizeBits div 8;
  Len := Length(Bytes);
  Blocks := Len div BytesC;
  Remain := Len mod BytesC;
  for i := 1 to Blocks do begin 
    Buffer := Copy(Bytes, (i - 1) * BytesC, BytesC);
    HCrypto_HEncryBITv2_Cipher.DecryptBlock_NExpanded(Buffer, Key);
    for k := 0 to BytesC - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
    Offset := Offset + BytesC;
  end;
  if Remain > 0 then begin
    Buffer := Copy(Bytes, Blocks * BytesC, Remain);
    HCrypto_HEncryBITv2_Cipher.DecryptBlock_NExpanded(Buffer, Key);
    for k := 0 to Remain - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
  end;

  SetLength(Bytes, Size);
  { All done. }
end;

class procedure HCrypto_HEncryBITv2_Cipher.EncryptBlock_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey);
begin
  HCrypto_RORBits(Bytes, Key.OverallShift);
  HCrypto_XorBufferFastLimited(Bytes, Key.EncryptionKey);
end;

class procedure HCrypto_HEncryBITv2_Cipher.EncryptBlock_NExpanded(var Block: TBytesArray; Key: HCrypto_EncryBITv2_Key);
var i: Integer;
begin
  for i := 0 to Key.Rounds - 1 do begin 
    HCrypto_XorBufferFastLimited(Block, Key.EncryptionKey);
    HCrypto_RORBits(Block, HCrypto_DirectionToNumber(Key.PackedShifts[i].Value, Key.PackedShifts[i].Direction));
  end;
end;

class procedure HCrypto_HEncryBITv2_Cipher.Encrypt_Expanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_ExpandedKey);
var Offset, Blocks, Remain, Len, BytesC, i, k, Size: Int64;
    Buffer, LenArr: TBytesArray;
begin
  Offset := 0;
  BytesC := Key.BlockSize div 8;
  Len := Length(Bytes);
  Blocks := Len div BytesC;
//  Remain := Len mod BytesC;

  Size := Len;
  LenArr := HCrypto_TEqualizer<Int64>.ToBytes(Size);
  SetLength(LenArr, 8);
  Size := Length(LenArr);
  SetLength(Bytes, (Blocks + 1) * BytesC);
  Len := Length(Bytes);
  Blocks := Len div BytesC;
  Remain := Len mod BytesC;
  
  for i := 1 to Blocks do begin 
    Buffer := Copy(Bytes, (i - 1) * BytesC, BytesC);
    HCrypto_HEncryBITv2_Cipher.EncryptBlock_Expanded(Buffer, Key);
    for k := 0 to BytesC - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
    Offset := Offset + BytesC;
  end;
  if Remain > 0 then begin
    Buffer := Copy(Bytes, Blocks * BytesC, Remain);
    HCrypto_HEncryBITv2_Cipher.EncryptBlock_Expanded(Buffer, Key);
    for k := 0 to Remain - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
  end;

  SetLength(Bytes, Length(Bytes) + Size);
  for i := 0 to Size - 1 do
    Bytes[Offset + i] := LenArr[i];
  { All done. }
end;

class procedure HCrypto_HEncryBITv2_Cipher.Encrypt_NExpanded(var Bytes: TBytesArray; Key: HCrypto_EncryBITv2_Key);
var Offset, Blocks, Remain, Len, BytesC, i, k, Size: Int64;
    Buffer, LenArr: TBytesArray;
begin
  Offset := 0;
  BytesC := Key.BlockSizeBits div 8;
  Len := Length(Bytes);
  Blocks := Len div BytesC;
//  Remain := Len mod BytesC;

  Size := Len;
  LenArr := HCrypto_TEqualizer<Int64>.ToBytes(Size);
  SetLength(LenArr, 8);
  Size := Length(LenArr);
  SetLength(Bytes, (Blocks + 1) * BytesC);
  Len := Length(Bytes);
  Blocks := Len div BytesC;
  Remain := Len mod BytesC;
  
  for i := 1 to Blocks do begin 
    Buffer := Copy(Bytes, (i - 1) * BytesC, BytesC);
    HCrypto_HEncryBITv2_Cipher.EncryptBlock_NExpanded(Buffer, Key);
    for k := 0 to BytesC - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
    Offset := Offset + BytesC;
  end;
  if Remain > 0 then begin
    Buffer := Copy(Bytes, Blocks * BytesC, Remain);
    HCrypto_HEncryBITv2_Cipher.EncryptBlock_NExpanded(Buffer, Key);
    for k := 0 to Remain - 1 do begin 
      Bytes[Offset + k] := Buffer[k];
    end;
  end;
  
  SetLength(Bytes, Length(Bytes) + Size);
  for i := 0 to Size - 1 do
    Bytes[Offset + i] := LenArr[i];
  { All done. }
end;

end.
