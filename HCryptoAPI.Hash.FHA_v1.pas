unit HCryptoAPI.Hash.FHA_v1;

{ Implents a File Hashing Algorithm }
{ Better version of CRC32 (CRC*) }

interface

uses
  System.SysUtils,
  System.Types,
  System.Classes,
  HCryptoAPI.Types,
  HCryptoAPI.Commons,
  HCryptoAPI.Hash.Raw_v1,
  HCryptoAPI.Hash.KHA_v1;

function HCrypto_HFHAv12_Hash(const FileStream: TFileStream; const Size: Integer = 256; const ChunkSize: Integer = 65536): TBytesArray;
function HCrypto_HFHAv12_SecureHash(const FileStream: TFileStream; const Size: Integer = 256; const ChunkSize: Integer = 65536): TBytesArray;
function HCrypto_HFHAv12_SecureKeyHash(const FileStream: TFileStream; const Key: TBytesArray; const HSize: Integer = 256; const Rounds: Integer = 256; const Size: Integer = 256; const ChunkSize: Integer = 65536): TBytesArray;

implementation

function HCrypto_HFHAv12_Hash(const FileStream: TFileStream; const Size: Integer = 256; const ChunkSize: Integer = 65536): TBytesArray;
var Len: Int64;
    i, k, Pos, Chunks, Remain: Integer;
    Storage: TBytesArray;
begin
  Pos := 0;
  HCrypto_ReLength(Result, Size);
  FileStream.Position := 0;
  Len := FileStream.Size;
  Chunks := Len div ChunkSize;
  Remain := Len mod ChunkSize;
  HCrypto_ReLength(Storage, ChunkSize);
  for i := 1 to Chunks do begin
    FileStream.Read(Storage[0], ChunkSize);
    for k := 0 to ChunkSize - 1 do begin
      Result[Pos] := Result[Pos] xor Storage[k];
      Pos := (Pos + 1) mod Size;
    end;
  end;
  if Remain > 0 then begin
    HCrypto_ReLength(Storage, Remain);
    FileStream.Read(Storage, Remain);
    for k := 0 to Remain - 1 do begin
      Result[Pos] := Result[Pos] xor Storage[k];
      Pos := (Pos + 1) mod Size;
    end;
  end;
end;

function HCrypto_HFHAv12_SecureHash(const FileStream: TFileStream; const Size: Integer = 256; const ChunkSize: Integer = 65536): TBytesArray;
begin
  Result := HCrypto_HRv1_Hash(HCrypto_HFHAv12_Hash(FileStream, Size, ChunkSize));
end;

function HCrypto_HFHAv12_SecureKeyHash(const FileStream: TFileStream; const Key: TBytesArray; const HSize: Integer = 256; const Rounds: Integer = 256; const Size: Integer = 256; const ChunkSize: Integer = 65536): TBytesArray;
begin
  Result := HCrypto_HKHA_v1_Hash(HCrypto_HFHAv12_Hash(FileStream, Size, ChunkSize), Key, HSize, Rounds);
end;

end.
