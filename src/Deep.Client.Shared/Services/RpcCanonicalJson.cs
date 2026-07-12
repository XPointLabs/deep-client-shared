using System.Security.Cryptography;
using System.Text.Json;

namespace Deep.Client.Shared.Services;

public static class RpcCanonicalJson
{
    public static byte[] Serialize(JsonElement value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            WriteValue(writer, value);
        }

        return stream.ToArray();
    }

    public static string Sha256Hex(JsonElement value)
    {
        return Convert.ToHexString(SHA256.HashData(Serialize(value))).ToLowerInvariant();
    }

    private static void WriteValue(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in value.EnumerateObject().OrderBy(static item => item.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteValue(writer, property.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray())
                {
                    WriteValue(writer, item);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(value.GetString());
                break;

            case JsonValueKind.Number:
                WriteNumber(writer, value);
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;

            default:
                throw new JsonException($"Unsupported JSON value kind {value.ValueKind}.");
        }
    }

    private static void WriteNumber(Utf8JsonWriter writer, JsonElement value)
    {
        if (value.TryGetInt64(out var signed))
        {
            writer.WriteNumberValue(signed);
            return;
        }

        if (value.TryGetUInt64(out var unsigned))
        {
            writer.WriteNumberValue(unsigned);
            return;
        }

        if (value.TryGetDecimal(out var decimalValue))
        {
            writer.WriteNumberValue(decimalValue);
            return;
        }

        writer.WriteNumberValue(value.GetDouble());
    }
}
