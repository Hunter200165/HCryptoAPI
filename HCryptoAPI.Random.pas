unit HCryptoAPI.Random;

interface

uses
  System.Types,
  System.Classes,
  HCryptoAPI.Types;

type
  HCrypto_TRandom<T> = class(TObject)
  public
    class function GetRandom: T; static;
  end;
  HCrypto_TPseudoRandom<T> = class(TObject)
  public
    class function GetRandom: T; static;
  end;

function HCrypto_RawRandomByte: Byte; assembler; forward;
function HCrypto_RandomByte: Byte;
function HCrypto_RandomInt: Integer;
function HCrypto_RandomRange(const Min, Max: Integer): Integer; overload;
function HCrypto_RandomRange(const Min, Max: Byte): Byte; overload;
function HCrypto_RandomBoolean: Boolean;
function HCrypto_PseudoRandomBoolean: Boolean;

implementation

function HCrypto_RawRandomByte: Byte; assembler;
asm
  xor EAX, EAX;
  rdtsc;
  mov Result, AL;
end;

function HCrypto_RandomByte: Byte;
var i: Byte;
begin
  Result := HCrypto_RawRandomByte;
  for i := 1 to Random(128) do begin
    Result := ((Result xor HCrypto_RawRandomByte) + HCrypto_RawRandomByte) mod 256;
  end;
  { Perditio Potesta Et }
  Result := Byte((Result xor HCrypto_RawRandomByte) + HCrypto_RawRandomByte - Random(256));
end;

function HCrypto_RandomRange(const Min, Max: Integer): Integer; overload;
begin
  Result := Random(Max - Min + 1) + Min;
end;

function HCrypto_RandomRange(const Min, Max: Byte): Byte; overload;
begin
  Result := Random(Max - Min + 1) + Min;
end;

function HCrypto_RandomInt: Integer;
var Block: array[1..4] of byte absolute Result;
    i: Integer;
begin
  for i := 1 to 4 do
    Block[i] := HCrypto_RandomByte;
end;

function HCrypto_RandomBoolean: Boolean;
var Output, Bit: Byte;
begin
  Output := HCrypto_RandomByte;
  asm
    XOR EAX, EAX;
    MOV AL, OUTPUT;
    SHR AL, 1;
    MOV Bit, 0;
    JNC @@AExit;
    MOV Bit, 1;
    @@AExit:
  end;
  Result := Boolean(Bit);
end;

function HCrypto_PseudoRandomBoolean: Boolean;
var Output, Bit: Byte;
begin
  Output := Random(256);
  asm
    XOR EAX, EAX;
    MOV AL, OUTPUT;
    SHR AL, 1;
    MOV Bit, 0;
    JNC @@AExit;
    MOV Bit, 1;
    @@AExit:
  end;
  Result := Boolean(Bit);
end;

{ HCrypto_TRandom<T> }

class function HCrypto_TRandom<T>.GetRandom: T;
var Block: array of byte;
    Size, i: Integer;
begin
  Size := SizeOf(T);
  SetLength(Block, Size);
  for i := 0 to Size - 1 do
    Block[i] := HCrypto_RandomByte;
  Move(Block[0], Result, Size);
end;

{ HCrypto_TPseudoRandom<T> }

class function HCrypto_TPseudoRandom<T>.GetRandom: T;
var Block: array of byte;
    Size, i: Integer;
begin
  Size := SizeOf(T);
  SetLength(Block, Size);
  for i := 0 to Size - 1 do
    Block[i] := Random(256); {0 - 255}
  Move(Block[0], Result, Size);
end;

end.
