from marshmallow import Schema, fields


class Observable(Schema):
    type = fields.String(required=True)
    value = fields.String(required=True)


observables = Observable(many=True)
