unit HCryptoAPI.Commons;

interface

uses
  System.SysUtils,
  System.Math,
  HCryptoAPI.Types,
  HCryptoAPI.Random,
  HCryptoAPI.Assembler;

{ Exports functions }

function HCrypto_StringToBytes(const S: String): TBytesArray;
function HCrypto_StringToBytes_ASCII(const S: String): TBytesArray; deprecated 'Use UTF8 instead.';
function HCrypto_BytesToString(const Bytes: TBytesArray): String;
function HCrypto_BytesToString_ASCII(const Bytes: TBytesArray): String; deprecated 'Use UTF8 instead.';
function HCrypto_UpDiv(const A, B: Integer): Integer;
function HCrypto_CopyBytes(const Bytes: TBytesArray): TBytesArray;
function HCrypto_GetBytesSum(const Bytes: TBytesArray): UInt64;
function HCrypto_Bits(const A: Integer): Integer; overload;
function HCrypto_Bits(const Bytes: TBytesArray): Integer; overload;
function HCrypto_Direction(const A: Byte): Boolean; overload;
function HCrypto_Direction(const A: Int64): Boolean; overload;
function HCrypto_DirectionToNumber(const Shift: Int64; const Direction: Boolean): Int64;
function HCrypto_GetNumberSize(const Number: UInt64): Integer;
function HCrypto_GetNumberByteSize(const Number: UInt64): Integer;
function HCrypto_StripBytes(const Bytes: TBytesArray; const ByteToStrip: Byte = 0): TBytesArray;
function HCrypto_StripBytesLeft(const Bytes: TBytesArray; const ByteToStrip: Byte = 0): TBytesArray;
function HCrypto_StripBytesRight(const Bytes: TBytesArray; const ByteToStrip: Byte = 0): TBytesArray;
function HCrypto_XorBuffer(const Bytes, Key: TBytesArray): TBytesArray;
function HCrypto_AppendBytes(const Bytes, Append: TBytesArray): TBytesArray;
function HCrypto_AreEqualBytes(const AIn, AComp: TBytesArray): Boolean;

function HCrypto_HashToString(const Bytes: TBytesArray; const NeedToLower: Boolean = False): String;
function HCrypto_BinToHex(const Bytes: TBytesArray; const NeedToLower: Boolean = False): String;
function HCrypto_ConcatToString(const Ints: TInt64sArray; const ConString: String = ' '): String;

function HCrypto_RandomBuffer(const Count: Integer): TBytesArray;
function HCrypto_PseudoRandomBuffer(const Count: Integer): TBytesArray;
function HCrypto_Encrypt(const Algorithm: TCipherFunction; const Bytes, Key: TBytesArray): TBytesArray;

function HCrypto_RandomString(const Len: Integer; const MinChar: Byte = 0; const MaxChar: Byte = 255): String;
function HCrypto_RandomReadableString(const Len: Integer): String;
function HCrypto_RandomASCIIString(const Len: Integer): String;

function HCrypto_GreatestCommonDivisor(A, B: Int64): Int64;
function HCrypto_AreRelativePrimes(const Numbers: TInt64sArray): Boolean;
function HCrypto_IsPrime(const Number: UInt64): Boolean;
function HCrypto_NextPrime(const Prime: UInt64): UInt64;
function HCrypto_FactorNumber(Number: UInt64): TUInt64sArray;
function HCrypto_FactorNumberCallbacked(Number: UInt64; OnFactor: TFactorCallback): TUInt64sArray;

procedure HCrypto_ReLength(var Bytes: TBytesArray; const Len: Integer);
procedure HCrypto_ClearBytes(var Bytes: TBytesArray; const Fill: Byte = 0);
procedure HCrypto_IncLength(var Bytes: TBytesArray; const Add: Integer);
procedure HCrypto_DecLength(var Bytes: TBytesArray; const Dec: Integer);
procedure HCrypto_ROLBits(var Bytes: TBytesArray; const Count: Int64 = 1);
procedure HCrypto_RORBits(var Bytes: TBytesArray; const Count: Int64 = 1);
procedure HCrypto_XorBufferFastLimited(var Buffer: TBytesArray; const Key: TBytesArray);

implementation

function HCrypto_StringToBytes(const S: String): TBytesArray;
begin
  Result := TBytesArray(TEncoding.UTF8.GetBytes(S));
end;

function HCrypto_StringToBytes_ASCII(const S: String): TBytesArray;
begin
  Result := TBytesArray(TEncoding.ASCII.GetBytes(S));
end;

function HCrypto_BytesToString(const Bytes: TBytesArray): String;
begin
  Result := TEncoding.UTF8.GetString(TBytes(Bytes));
end;

function HCrypto_BytesToString_ASCII(const Bytes: TBytesArray): String;
begin
  Result := TEncoding.ASCII.GetString(TBytes(Bytes));
end;

function HCrypto_UpDiv(const A, B: Integer): Integer;
begin
  Result := Ceil(A / B);
end;

procedure HCrypto_ReLength(var Bytes: TBytesArray; const Len: Integer);
begin
  SetLength(Bytes, 0);
  SetLength(Bytes, Len);
end;

procedure HCrypto_IncLength(var Bytes: TBytesArray; const Add: Integer);
begin
  SetLength(Bytes, Length(Bytes) + Add);
end;

procedure HCrypto_DecLength(var Bytes: TBytesArray; const Dec: Integer);
begin
  SetLength(Bytes, Length(Bytes) - Dec);
end;

function HCrypto_CopyBytes(const Bytes: TBytesArray): TBytesArray;
begin
  Result := Copy(Bytes, 0, Length(Bytes));
end;

function HCrypto_AppendBytes(const Bytes, Append: TBytesArray): TBytesArray;
var i, Len, LenApp: Integer;
begin
  Result := HCrypto_CopyBytes(Bytes);
  Len := Length(Result);
  LenApp := Length(Append);
  SetLength(Result, Len + LenApp);
  for i := 0 to LenApp - 1 do
    Result[Len + i] := Append[i];
end;

function HCrypto_StripBytesLeft(const Bytes: TBytesArray; const ByteToStrip: Byte = 0): TBytesArray;
var Min, i: Integer;
begin
  Min := 0;
  Result.ReLength(0);
  for i := 0 to Bytes.Size - 1 do begin
    if Bytes[i] <> ByteToStrip then begin
      Min := i;
      Break;
    end;
  end;
  for i := Min to Bytes.Size - 1 do
    Result.AppendByte(Bytes[i]);
end;

function HCrypto_StripBytesRight(const Bytes: TBytesArray; const ByteToStrip: Byte = 0): TBytesArray;
var Max, i: Integer;
begin
  Max := Bytes.Size - 1;
  Result.ReLength(0);
  for i := Bytes.Size - 1 downto 0 do begin
    if Bytes[i] <> ByteToStrip then begin
      Max := i;
      Break;
    end;
  end;
  for i := 0 to Max do
    Result.AppendByte(Bytes[i]);
end;

function HCrypto_StripBytes(const Bytes: TBytesArray; const ByteToStrip: Byte = 0): TBytesArray;
  procedure AddElement(const Element: Byte);
  begin
    SetLength(Result, Length(Result) + 1);
    Result[Length(Result) - 1] := Element;
  end;
var Min, Max, Len, i: Integer;
begin
  SetLength(Result, 0);
  Min := 0;
  Len := Length(Bytes);
  Max := Len - 1;
  for i := 0 to Len - 1 do
    if Bytes[i] = ByteToStrip then
      Min := i
    else begin
      Min := i;
      break;
    end;

  for i := Len - 1 downto 0 do
    if Bytes[i] = ByteToStrip then
      Max := i
    else begin
      Max := i;
      break;
    end;
  for i := Min to Max do
    AddElement(Bytes[i]);
end;

function HCrypto_GetBytesSum(const Bytes: TBytesArray): UInt64;
var i: Integer;
begin
  Result := 0;
  for i := 0 to Length(Bytes) - 1 do begin
    Result := Result + Bytes[i];
  end;
end;

function HCrypto_Bits(const A: Integer): Integer; overload;
begin
  Result := A * 8;
end;

function HCrypto_Bits(const Bytes: TBytesArray): Integer; overload;
begin
  Result := HCrypto_Bits(Length(Bytes));
end;

procedure HCrypto_ClearBytes(var Bytes: TBytesArray; const Fill: Byte = 0);
begin
  FillChar(Bytes[0], Length(Bytes), Fill);
end;

function HCrypto_XorBuffer(const Bytes, Key: TBytesArray): TBytesArray;
var Len, LenK, LenO, i: Integer;
begin
  Len := Length(Bytes);
  LenK := Length(Key);
  if Len > LenK then
    LenO := Len
  else
    LenO := LenK;
  HCrypto_ReLength(Result, LenO);
  for i := 0 to LenO - 1 do begin
    if i in [0..Len - 1] then
      Result[i] := Result[i] xor Bytes[i];
    if i in [0..LenK - 1] then
      Result[i] := Result[i] xor Key[i];
  end;
end;

procedure HCrypto_XorBufferFastLimited(var Buffer: TBytesArray; const Key: TBytesArray);
var Len, LenK, i: Integer;
begin
  Len := Length(Buffer);
  LenK := Length(Key);
  if LenK < Len then
    Len := LenK;
  for i := 0 to Len - 1 do
    Buffer[i] := Buffer[i] xor Key[i];
end;

function HCrypto_AreEqualBytes(const AIn, AComp: TBytesArray): Boolean;
var i: Integer;
begin
  Result := True;
  if AIn.Size <> AComp.Size then begin
    Result := False;
    Exit;
  end;
  for i := 0 to AIn.Size - 1 do
    if AIn[i] <> AComp[i] then begin
      Result := False;
      Exit;
    end;
end;

function HCrypto_RandomBuffer(const Count: Integer): TBytesArray;
var i: Integer;
begin
  HCrypto_ReLength(Result, Count);
  for i := 0 to Count - 1 do
    Result[i] := HCrypto_RandomByte;
end;

function HCrypto_PseudoRandomBuffer(const Count: Integer): TBytesArray;
var i: Integer;
begin
  HCrypto_ReLength(Result, Count);
  for i := 0 to Count - 1 do
    Result[i] := Random(256);
end;

function HCrypto_GetNumberSize(const Number: UInt64): Integer;
var i: Integer;
begin
  i := 8;
  while ((Power(2, i) - 1) < Number) do begin
    i := i + 8;
  end;
  Result := i;
end;

function HCrypto_GetNumberByteSize(const Number: UInt64): Integer;
begin
  Result := HCrypto_GetNumberSize(Number) div 8;
end;

{ Hashes }

function HCrypto_HashToString(const Bytes: TBytesArray; const NeedToLower: Boolean = False): String;
var i: Integer;
begin
  Result := '';
  for i := 0 to Length(Bytes) - 1 do begin
    Result := Result + IntToHex(Bytes[i], 2);
  end;
  if NeedToLower then
    Result := LowerCase(Result);
end;

function HCrypto_BinToHex(const Bytes: TBytesArray; const NeedToLower: Boolean = False): String;
begin
  Result := HCrypto_HashToString(Bytes, NeedToLower);
end;

{ Direction }

{ If True then Right else Left; }

{ TABLE OF VALUES: }
{ TRUE = Right     }
{ FALSE = Left     }
{ > 0 = Right      }
{ < 0 = Left       }

{  Left(<0)     0     Right(>0) }
{  <------------|------------>  }
{  False      Undef       True  }
{  -128         0          127  } { Because ShortInt(128) = -1 }

function HCrypto_Direction(const A: Byte): Boolean; overload;
begin
  Result := A in [0..127];
end;

function HCrypto_Direction(const A: Int64): Boolean; overload;
begin
  Result := A >= 0;
end;

function HCrypto_DirectionToNumber(const Shift: Int64; const Direction: Boolean): Int64;
begin
  (* void main, haha *) {
  if not Direction then
    Result := - Shift
  else
    Result := Shift;
  }
  Result := (Byte(Direction) + -1) * Shift + (Byte(Direction) + 0) * Shift; { Faster? Significantly! }
end;

procedure HCrypto_RORBits(var Bytes: TBytesArray; const Count: Int64 = 1);
begin
  if Count > 0 then
    HCrypto_ASM_RORREGS(Bytes, Count)
  else
    HCrypto_ASM_ROLREGS(Bytes, - Count);
end;

procedure HCrypto_ROLBits(var Bytes: TBytesArray; const Count: Int64 = 1);
begin
  if Count > 0 then
    HCrypto_ASM_ROLREGS(Bytes, Count)
  else
    HCrypto_ASM_RORREGS(Bytes, - Count);
end;

{ Ciphers }

function HCrypto_Encrypt(const Algorithm: TCipherFunction; const Bytes, Key: TBytesArray): TBytesArray;
begin
  Result := HCrypto_CopyBytes(Bytes);
  Algorithm(Result, Key);
end;

{ Strings }

function HCrypto_RandomString(const Len: Integer; const MinChar: Byte = 0; const MaxChar: Byte = 255): String;
var i: Integer;
begin
  Result := '';
  for i := 1 to Len do
    Result := Result + Chr(HCrypto_RandomRange(MinChar, MaxChar));
end;

function HCrypto_RandomReadableString(const Len: Integer): String;
begin
  Result := HCrypto_RandomString(Len, 33, 254);
end;

function HCrypto_RandomASCIIString(const Len: Integer): String;
begin
  Result := HCrypto_RandomString(Len, 33, 127);
end;

function HCrypto_ConcatToString(const Ints: TInt64sArray; const ConString: String = ' '): String;
var i: Integer;
begin
  Result := '';
  if Ints.Size <= 0 then Exit;
  for i := 0 to Ints.Size - 2 do
    Result := Result + Ints[i].ToString + ConString;
  Result := Result + Ints[Ints.Size - 1].ToString;
end;

{ Relative Primes }

function HCrypto_GreatestCommonDivisor(A, B: Int64): Int64;
var C: Int64;
begin
  C := B mod A;
  if C = 0 then
    Result := A
  else
    Result := HCrypto_GreatestCommonDivisor(B, A mod B);
end;

function HCrypto_AreRelativePrimes(const Numbers: TInt64sArray): Boolean;
var i: Integer;
    k: Integer;
begin
  Result := true;
  for i := 0 to Length(Numbers) - 1 do begin
    for k := i + 1 to Length(Numbers) - 1 do begin
      Result := Result and (HCrypto_GreatestCommonDivisor(Numbers[i], Numbers[k]) = 1);
      if not Result then
        Break;
    end;
    if not Result then
      Break;
  end;
end;

{ Primes }

function HCrypto_IsPrime(const Number: UInt64): Boolean;
var Limit, i: UInt64;
begin
  Limit := Ceil(Sqrt(Number));
  Result := True;
  for i := 2 to Limit do begin
    if HCrypto_GreatestCommonDivisor(Number, i) <> 1 then
      Result := False;
  end;
end;

function HCrypto_NextPrime(const Prime: UInt64): UInt64;
begin
  Result := Prime;
  if (Prime mod 2) = 0 then
    Result := Prime + 1
  else
    Result := Result + 2;
  while not HCrypto_IsPrime(Result) do
    Result := Result + 2;
end;

function HCrypto_FactorNumber(Number: UInt64): TUInt64sArray;
var Primes: TUInt64sArray;
    i: Integer;
    Check: Boolean;
begin
  SetLength(Result, 0);
  { Initial prime }
  Primes.AppendUInt64(2);
  while not HCrypto_IsPrime(Number) do begin
    Check := False;
    for i := 0 to Primes.Size - 1 do
      if (Number mod Primes[i]) = 0 then begin
        Result.AppendUInt64(Primes[i]);
        Number := Number div Primes[i];
        Check := True;
        Break;
      end;
    if Check then Continue;
    repeat
      Primes.AppendUInt64(HCrypto_NextPrime(Primes[Primes.Size - 1]));
    until (Number mod Primes[Primes.Size - 1]) = 0;
    Result.AppendUInt64(Primes[Primes.Size - 1]);
    Number := Number div Primes[Primes.Size - 1];
  end;
  if Number > 1 then
    Result.AppendUInt64(Number);
end;

function HCrypto_FactorNumberCallbacked(Number: UInt64; OnFactor: TFactorCallback): TUInt64sArray;
var Primes: TUInt64sArray;
    i: Integer;
    Check: Boolean;
begin
  SetLength(Result, 0);
  { Initial prime }
  Primes.AppendUInt64(2);
  while not HCrypto_IsPrime(Number) do begin
    Check := False;
    for i := 0 to Primes.Size - 1 do
      if (Number mod Primes[i]) = 0 then begin
        Result.AppendUInt64(Primes[i]);
        Number := Number div Primes[i];
        OnFactor(Primes[i], Number);
        Check := True;
        Break;
      end;
    if Check then Continue;
    repeat
      Primes.AppendUInt64(HCrypto_NextPrime(Primes[Primes.Size - 1]));
    until (Number mod Primes[Primes.Size - 1]) = 0;
    Result.AppendUInt64(Primes[Primes.Size - 1]);
    Number := Number div Primes[Primes.Size - 1];
    OnFactor(Primes[Primes.Size - 1], Number);
  end;
  if Number > 1 then begin
    Result.AppendUInt64(Number);
    OnFactor(Number, 1);
  end;
end;

end.
