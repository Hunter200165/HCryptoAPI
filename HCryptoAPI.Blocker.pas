unit HCryptoAPI.Blocker;

interface

uses
  HCryptoAPI.Types;

type
  HCrypto_Blocker_CallbackFunction = procedure(var Bytes: TBytesArray; const Size: Integer);
  HCrypto_TBlocker = class(TObject)
  public
    class procedure SplitToBlocks(const Bytes: TBytesArray; const Size: Integer; Callback: HCrypto_Blocker_CallbackFunction);
  end;

implementation

{ HCrypto_TBlocker }

class procedure HCrypto_TBlocker.SplitToBlocks(const Bytes: TBytesArray; const Size: Integer; Callback: HCrypto_Blocker_CallbackFunction);
var Blocks, Remains, Len, i: Int64;
    Buffer: TBytesArray;
begin
  Len := Length(Bytes);
  Blocks := Len div Size;
  Remains := Len mod Size;
  for i := 1 to Blocks do begin
    Buffer := Copy(Bytes, (i - 1) * Size, Size);
    Callback(Buffer, Size);
  end;
  if Remains > 0 then begin
    Buffer := Copy(Bytes, Blocks * Size, Remains);
    Callback(Buffer, Remains);
  end;
end;

end.
