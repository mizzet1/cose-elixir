defmodule COSETest.ECCKey do
  use ExUnit.Case

  alias COSE.Keys.ECC

  @kty 1
  @crv -1
  @x -2
  @y -3

  describe "ECC.from_cbor_map/1" do
    test "accepts a valid P-256 COSE_Key map" do
      key = ECC.generate(:es256)
      cbor_map = %{@kty => "ecc", @crv => "p256", @x => key.x, @y => key.y}

      assert {:ok, parsed} = ECC.from_cbor_map(cbor_map)
      assert parsed.kty == :ecc
      assert parsed.crv == :p256
      assert parsed.alg == :es256
      assert parsed.x == key.x
      assert parsed.y == key.y
    end

    test "rejects coordinate of wrong size" do
      cbor_map = %{@kty => "ecc", @crv => "p256", @x => :binary.copy(<<0>>, 31), @y => :binary.copy(<<0>>, 32)}
      assert {:error, :invalid_cose_key} = ECC.from_cbor_map(cbor_map)
    end

    test "rejects unrecognized map" do
      assert {:error, :invalid_cose_key} = ECC.from_cbor_map(%{})
    end
  end
end
