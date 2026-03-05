defmodule COSE.Keys.Symmetric do
  use TypedEctoSchema

  @primary_key false
  typed_embedded_schema do
    field :kid, :binary
    field :alg, Ecto.Enum, values: COSE.cose_algs_kv()
    field :key_ops, {:array, :string}
    field :base_iv, :binary
    field :k, :binary
  end
end
