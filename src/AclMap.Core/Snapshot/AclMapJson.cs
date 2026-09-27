using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using AclMap.Models.Snapshot;

namespace AclMap.Core.Snapshot;

/// <summary>Options JSON communes (camelCase, énumérations en texte).</summary>
public static class AclMapJson
{
    /// <summary>Options de sérialisation.</summary>
    public static readonly JsonSerializerOptions Options = Create(false);

    /// <summary>Options avec indentation (fichiers lisibles).</summary>
    public static readonly JsonSerializerOptions Indented = Create(true);

    private static JsonSerializerOptions Create(bool indented)
    {
        var o = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = indented,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            PropertyNameCaseInsensitive = true,
        };
        o.Converters.Add(new JsonStringEnumConverter());
        o.Converters.Add(new FolderNodeConverter());
        return o;
    }

    /// <summary>Dossier sérialisé en tableau compact [id, parent, nom, sd, drapeaux] (instantanés volumineux).</summary>
    public sealed class FolderNodeConverter : JsonConverter<FolderNode>
    {
        public override FolderNode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartArray) throw new JsonException("Dossier : tableau attendu.");
            reader.Read(); var id = reader.GetInt32();
            reader.Read(); var parent = reader.GetInt32();
            reader.Read(); var name = reader.GetString() ?? "";
            reader.Read(); var sd = reader.GetInt32();
            reader.Read(); var flags = (NodeFlags)reader.GetInt32();
            reader.Read();
            if (reader.TokenType != JsonTokenType.EndArray) throw new JsonException("Dossier : tableau de 5 éléments attendu.");
            return new FolderNode(id, parent, name, sd, flags);
        }

        public override void Write(Utf8JsonWriter writer, FolderNode value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            writer.WriteNumberValue(value.Id); writer.WriteNumberValue(value.ParentId); writer.WriteStringValue(value.Name);
            writer.WriteNumberValue(value.SdId); writer.WriteNumberValue((int)value.Flags);
            writer.WriteEndArray();
        }
    }
}
