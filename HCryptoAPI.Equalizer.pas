unit HCryptoAPI.Equalizer;

interface

uses
  HCryptoAPI.Types;

type
  HCrypto_TEqualizer<T> = class(TObject)
  public
    class function FromBytes(const Bytes: TBytesArray): T; static;
    class function ToBytes(Value: T): TBytesArray; static;
end;

implementation

{ HCrypto_TEqualizer<T> }

class function HCrypto_TEqualizer<T>.FromBytes(const Bytes: TBytesArray): T;
var i, Max, Size, Len, Sub: Integer;
    Val: T;
    Storage: TBytesArray;
begin
  Size := SizeOf(T);
  Len := Length(Bytes);
  SetLength(Storage, 0);
  SetLength(Storage, Size);
  Move(Storage[0], Val, Size);
  Sub := 0;
  if Len < Size then begin
    Sub := Size - Len;
    Size := Len;
  end;
  for i := 0 to Size - 1 do begin
    Storage[i] := Bytes[i];
  end;
  Move(Storage[0], Val, SizeOf(T)); // We will transform only low bytes
  Result := Val;
end;

class function HCrypto_TEqualizer<T>.ToBytes(Value: T): TBytesArray;
var Size: Integer;
begin
  Size := SizeOf(T);
  SetLength(Result, Size);
  Move(Value, Result[0], Size);
end;

end.
