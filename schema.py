from marshmallow import Schema, fields
from marshmallow_geojson import GeoJSONSchema

class BaseSchema(Schema):
    location = fields.Nested(GeoJSONSchema)
    data = fields.Dict(required=True)
    
    def to_dict():
        return {
            'location': {
                'type': 'Point',
                'coordinates': [0, 0]
            },
            'data': {
                'key':'value'
            }
        }
