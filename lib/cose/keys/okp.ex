defmodule COSE.Keys.OKP do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

  def generate(:enc) do
    {x, d} = :crypto.generate_key(:eddh, :x25519)

    %__MODULE__{
      kty: :okp,
      crv: :x25519,
      x: x,
      d: d
    }
  end

  def generate(:sig) do
    {x, d} = :crypto.generate_key(:eddsa, :ed25519)

    %__MODULE__{
      kty: :okp,
      crv: :ed25519,
      x: x,
      d: d
    }
  end
end

defimpl COSE.Keys.Key, for: COSE.Keys.OKP do
  @kty 1
  @crv -1
  @x -2

  @crv_enum Ecto.ParameterizedType.init(Ecto.Enum, values: [x25519: 4, ed25519: 6])

  def sign(key, digest_type, to_be_signed) do
    signature = :crypto.sign(:eddsa, digest_type, to_be_signed, [key.d, :ed25519])
    {:ok, signature}
  end

  def verify(ver_key, digest_type, to_be_verified, signature) do
    case :crypto.verify(:eddsa, digest_type, to_be_verified, signature, [ver_key.x, :ed25519]) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  def encode(key),
    do: %{@kty => 1, @crv => encode_crv(key.crv), @x => key.x}

  defp encode_crv(crv) do
    {:ok, int} = Ecto.Type.dump(@crv_enum, crv)
    int
  end
end
