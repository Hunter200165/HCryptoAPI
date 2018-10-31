unit HCryptoAPI.Hash.Raw_v1;

{ Slow, monumental and very strong Hash }
{ It is Raw, because it is used in other hash functions as a base. }

interface

uses
  HCryptoAPI.Types,
  HCryptoAPI.Commons,
  HCryptoAPI.Assembler;

function HCrypto_HRv1_Hash(const Bytes: TBytesArray): TBytesArray; overload;
function HCrypto_HRv1_Hash(const S: String): TBytesArray; overload;

implementation

const
  HCrypto_HRv1_Rounds = 256;
  HCrypto_HRv1_Size = HCrypto_HRv1_Rounds div 2;

function HCrypto_HRv1_Hash(const Bytes: TBytesArray): TBytesArray; overload;
var i, n, m, LB, Len, k, Pos: Integer;
    BytesLeft, BytesRight, BytesMiddle: TBytesArray;
begin
  Pos := 0;
  HCrypto_ReLength(Result, HCrypto_HRv1_Size);
  BytesLeft := HCrypto_CopyBytes(Bytes);
  BytesRight := HCrypto_CopyBytes(Bytes);
  Len := Length(Bytes);
  LB := HCrypto_Bits(Len);
  BytesMiddle := HCrypto_CopyBytes(Bytes);
  if Len <= 0 then
    Exit;
  for i := 1 to HCrypto_HRv1_Rounds do begin
    n := HCrypto_GetBytesSum(Result) mod UInt64(LB);
    m := n div 2 - 1;
    HCrypto_ASM_ROLREGS(BytesLeft, n);
    HCrypto_ASM_RORREGS(BytesRight, m);
    for k := 0 to Len - 1 do begin
      BytesMiddle[k] := BytesMiddle[k] xor
                        BytesLeft[k] xor
                        BytesRight[k];
      Result[Pos] := Result[Pos] xor
                     BytesMiddle[k];
      Pos := (Pos + 1) mod HCrypto_HRv1_Size;
    end;
  end;
end;

function HCrypto_HRv1_Hash(const S: String): TBytesArray; overload;
begin
  Result := HCrypto_HRv1_Hash(HCrypto_StringToBytes(S));
end;

end.
