defmodule COSETest.OKPKey do
  use ExUnit.Case

  alias COSE.Keys.OKP

  @kty 1
  @crv -1
  @x -2

  describe "OKP.from_cbor_map/1" do
    test "accepts a valid X25519 COSE_Key map" do
      key = OKP.generate(:enc)
      cbor_map = %{@kty => "okp", @crv => "x25519", @x => key.x}

      assert {:ok, parsed} = OKP.from_cbor_map(cbor_map)
      assert parsed.kty == :okp
      assert parsed.crv == :x25519
      assert parsed.x == key.x
    end

    test "rejects x coordinate of wrong size" do
      cbor_map = %{@kty => "okp", @crv => "x25519", @x => :binary.copy(<<0>>, 31)}
      assert {:error, :invalid_cose_key} = OKP.from_cbor_map(cbor_map)
    end

    test "rejects unrecognized map" do
      assert {:error, :invalid_cose_key} = OKP.from_cbor_map(%{})
    end
  end
end
