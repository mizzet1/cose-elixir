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

  describe "ECC.decode/1" do
    test "is exported" do
      assert function_exported?(ECC, :decode, 1)
    end

    test "accepts a wire-format P-256 map with tag-wrapped coordinates" do
      key = ECC.generate(:es256)

      cbor_map = %{
        @kty => 2,
        @crv => 1,
        @x => %CBOR.Tag{tag: :bytes, value: key.x},
        @y => %CBOR.Tag{tag: :bytes, value: key.y}
      }

      assert COSE.Keys.decode(cbor_map) ==
               {:ok, %ECC{kty: :ecc, crv: :p256, alg: :es256, x: key.x, y: key.y}}
    end

    test "accepts a wire-format P-256 map with raw-binary coordinates" do
      key = ECC.generate(:es256)
      cbor_map = %{@kty => 2, @crv => 1, @x => key.x, @y => key.y}

      assert COSE.Keys.decode(cbor_map) ==
               {:ok, %ECC{kty: :ecc, crv: :p256, alg: :es256, x: key.x, y: key.y}}
    end

    test "decodes a real device InitExchange COSE_Key vector" do
      init_exchange =
        "hAAAWEukAQIgASFYICV5oFsNuKnLG4mnGSBH+GMy+WBqJ7yx41zbBh797sxeIlggqQh8qiH0LmbG9CMLEp2d1tbh0kgEqCTJYuE1o2nZv8dYIHVF/77o2ZV6W1CQjpC00lgpiddAOx0LB7AQ+WfuaCUf"
        |> Base.decode64!()

      {:ok, [_seq, _alg, %CBOR.Tag{tag: :bytes, value: cose_key_bstr}, _salt], ""} =
        CBOR.decode(init_exchange)

      {:ok, cose_key_map, ""} = CBOR.decode(cose_key_bstr)

      assert {:ok, %ECC{crv: :p256, alg: :es256, x: x, y: y}} = COSE.Keys.decode(cose_key_map)

      assert Base.encode16(x, case: :lower) ==
               "2579a05b0db8a9cb1b89a7192047f86332f9606a27bcb1e35cdb061efdeecc5e"

      assert Base.encode16(y, case: :lower) ==
               "a9087caa21f42e66c6f4230b129d9dd6d6e1d24804a824c962e135a369d9bfc7"
    end

    test "rejects an unknown kty" do
      assert {:error, :invalid_cose_key} = COSE.Keys.decode(%{@kty => 99})
    end

    test "rejects an unsupported crv" do
      cbor_map = %{
        @kty => 2,
        @crv => 99,
        @x => :binary.copy(<<0>>, 32),
        @y => :binary.copy(<<0>>, 32)
      }

      assert {:error, :invalid_cose_key} = ECC.decode(cbor_map)
    end

    test "rejects a coordinate of the wrong length" do
      cbor_map = %{
        @kty => 2,
        @crv => 1,
        @x => :binary.copy(<<0>>, 31),
        @y => :binary.copy(<<0>>, 32)
      }

      assert {:error, :invalid_cose_key} = ECC.decode(cbor_map)
    end
  end
end
