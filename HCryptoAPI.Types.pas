unit HCryptoAPI.Types;

interface

uses
  System.Classes,
  System.SysUtils;

type
  TCryptoArray = array of byte; { Useless at the moment. Do not use it }
  TBytesArray = array of byte;
  TIntegersArray = array of Integer;
  TInt64sArray = array of Int64;
  TUInt64sArray = array of UInt64;
  TStringsArray = array of String;

  TStringsArrayRecord = record
    Storage: TStringsArray;
    class operator in(A: String; B: TStringsArrayRecord): Boolean;
  end;

  { Feel free to expand it }
  TBytesHelper = record helper for TBytesArray
  private
    function GetSize: Integer;
    procedure SetSize(const Value: Integer);
  public
    property Size: Integer read GetSize write SetSize;

    procedure ReLength(const Count: Integer);
    procedure Append(const Bytes: TBytesArray);
    procedure AppendByte(const Data: Byte);
    function ToString: String;
    function ToString_ASCII: String;

    function ToHexString(const Lower: Boolean = True): string;
    function ToMemoryStream: TMemoryStream;
    class function FromMemoryStream(MemoryStream: TMemoryStream): TBytesArray; static;

    class function ReadFromStream(Stream: TStream; const Count: Int64): TBytesArray; static;
    procedure WriteToStream(Stream: TStream);
  end;

  TInt64sHelper = record helper for TInt64sArray
  private
    function GetSize: Integer;
    procedure SetSize(const Value: Integer);
  public
    property Size: Integer read GetSize write SetSize;
    procedure AppendInt64(const Data: Int64);
  end;

  TUInt64sHelper = record helper for TUInt64sArray
  private
    function GetSize: Integer;
    procedure SetSize(const Value: Integer);
  public
    property Size: Integer read GetSize write SetSize;
    procedure AppendUInt64(const Data: UInt64);
  end;

  TStringCryptoHelper = record helper for String
  public
    function ToBytes: TBytesArray;
    function ToBytes_ASCII: TBytesArray;
    function FromBytes(const Bytes: TBytesArray): string;
    function FromBytes_ASCII(const Bytes: TBytesArray): String;

    function Fmt(const FormatOptions: array of const): String;
  end;

  TStringsArrayHelper = record helper for TStringsArray
  public
    function GetRecord: TStringsArrayRecord;
  end;

  { Standard cipher function }
  { Could be expanded, using Encryptor }
  TCipherFunction = procedure(var Bytes: TBytesArray; const Key: TBytesArray);

  TFactorCallback = procedure(const Prime, Remain: UInt64);

implementation

{ TBytesHelper }

uses
  HCryptoAPI.Commons;

procedure TBytesHelper.Append(const Bytes: TBytesArray);
begin
  Self := HCrypto_AppendBytes(Self, Bytes);
end;

procedure TBytesHelper.AppendByte(const Data: Byte);
begin
  Self.Size := Self.Size + 1;
  Self[Self.Size - 1] := Data;
end;

class function TBytesHelper.FromMemoryStream(MemoryStream: TMemoryStream): TBytesArray;
var SizeM: Int64;
begin
  SizeM := MemoryStream.Size;
  Result.Size := SizeM;
  MemoryStream.Position := 0;
  MemoryStream.ReadBuffer(Result[0], SizeM);
end;

function TBytesHelper.GetSize: Integer;
begin
  Result := Length(Self);
end;

class function TBytesHelper.ReadFromStream(Stream: TStream; const Count: Int64): TBytesArray;
begin
  Result.Size := Count;
  Stream.ReadBuffer(Result[0], Count);
end;

procedure TBytesHelper.ReLength(const Count: Integer);
begin
  HCrypto_ReLength(Self, Count);
end;

procedure TBytesHelper.SetSize(const Value: Integer);
begin
  SetLength(Self, Value);
end;

function TBytesHelper.ToHexString(const Lower: Boolean): string;
begin
  Result := HCrypto_BinToHex(Self, Lower);
end;

function TBytesHelper.ToMemoryStream: TMemoryStream;
begin
  Result := TMemoryStream.Create;
  Result.Position := 0;
  Result.WriteBuffer(Self[0], Self.Size);
  Result.Position := 0;
end;

function TBytesHelper.ToString: String;
begin
  Result := HCrypto_BytesToString(Self);
end;

function TBytesHelper.ToString_ASCII: String;
begin
  {$WARNINGS OFF}
  Result := HCrypto_BytesToString_ASCII(Self);
  {$WARNINGS ON}
end;

procedure TBytesHelper.WriteToStream(Stream: TStream);
begin
  Stream.WriteBuffer(Self[0], Self.Size);
end;

{ TStringCryptoHelper }

function TStringCryptoHelper.Fmt(const FormatOptions: array of const): String;
begin
  Result := Format(Self, FormatOptions);
end;

function TStringCryptoHelper.FromBytes(const Bytes: TBytesArray): string;
begin
  Result := HCrypto_BytesToString(Bytes);
end;

function TStringCryptoHelper.FromBytes_ASCII(const Bytes: TBytesArray): String;
begin
  {$WARNINGS OFF}
  Result := HCrypto_BytesToString_ASCII(Bytes);
  {$WARNINGS ON}
end;

function TStringCryptoHelper.ToBytes: TBytesArray;
begin
  Result := HCrypto_StringToBytes(Self);
end;

function TStringCryptoHelper.ToBytes_ASCII: TBytesArray;
begin
  {$WARNINGS OFF}
  Result := HCrypto_StringToBytes_ASCII(Self);
  {$WARNINGS ON}
end;

{ TStringsArrayRecord }

class operator TStringsArrayRecord.in(A: String; B: TStringsArrayRecord): Boolean;
var i: Integer;
begin
  Result := False;
  for i := 0 to Length(B.Storage) - 1 do
    if A = B.Storage[i] then begin
      Result := True;
      Break;
    end;
end;

{ TStringsArrayHelper }

function TStringsArrayHelper.GetRecord: TStringsArrayRecord;
begin
  Result.Storage := Self;
end;

{ TInt64sHelper }

procedure TInt64sHelper.AppendInt64(const Data: Int64);
begin
  Size := Size + 1;
  Self[Size - 1] := Data;
end;

function TInt64sHelper.GetSize: Integer;
begin
  Result := Length(Self);
end;

procedure TInt64sHelper.SetSize(const Value: Integer);
begin
  SetLength(Self, Value);
end;

{ TUInt64sHelper }

procedure TUInt64sHelper.AppendUInt64(const Data: UInt64);
begin
  Size := Size + 1;
  Self[Size - 1] := Data;
end;

function TUInt64sHelper.GetSize: Integer;
begin
  Result := Length(Self);
end;

procedure TUInt64sHelper.SetSize(const Value: Integer);
begin
  SetLength(Self, Value);
end;

end.
