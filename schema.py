from marshmallow import Schema, fields
from marshmallow_geojson import GeoJSONSchema

class BaseSchema(Schema):
    location = fields.Nested(GeoJSONSchema)
    data = fields.Dict(required=True)
