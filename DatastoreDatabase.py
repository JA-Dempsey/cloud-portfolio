from google.cloud import datastore


class DatastoreDatabase():

    def __init__(self, url=None):
        self.client = datastore.Client()
        self._url = url

    def get(self, type, id=None, filters=None):

        output = None

        # Single entity when given an id
        if id:
            qkey = self.client.key(type, int(id))
            entity = self.client.get(qkey)
            output = self._convert_single(entity)
            return output

        # Remainder of options use this query def
        query = self.client.query(kind=type)

        # List of entities, no filters
        if not filters:
            entity_list = list(query.fetch())

        # Filter request
        else:
            for filter in filters:
                attr, op, val = filter
                query.add_filter(attr, op, val)

            entity_list = list(query.fetch())

        if entity_list:
            output = self._convert_list(entity_list)

        return output

    def create_single(self, type, data):
        """Method that creats an entity of a given type with the
        given data. Each entry in the data will correspond to an
        attribute of the entity."""
        qkey = self.client.key(type)

        # Create entity and modify it
        entity = datastore.Entity(key=qkey)

        for key in data.keys():
            entity[key] = data[key]

        self.client.put(entity)

        # Return the entity created in dict format
        return self._convert_single(entity)

    def update_single(self, type, id, data):
        """Method that updates an entity given the new data,
        and the id of the entity to change."""
        entity = self.get(type, id)

        if entity:
            for key in data.keys():
                entity[key] = data[key]
        else:
            return None  # No entity found with given type, id

    def delete_single(self, type, id):
        """Method that deletes a single entity give the type
        and id that exists in the database."""
        entity = self.get(type, id)
        output = self._convert_single(entity)

        if entity:
            qkey = self.client.key(type, id)
            self.client.delete(qkey)
            return output  # Return deleted info
        else:
            return None  # Nothing was deleted

    def _convert_single(self, entity):
        """Internal method that converts a datastore entity
        to a dict to make return with added data easier and
        closer to JSON format."""
        output = {}
        data = dict(entity)
        if entity.key.id:
            output['id'] = entity.key.id

        for key in data.keys():
            output[key] = data[key]

        return output

    def _convert_list(self, entities):
        """Give a list of entities, converts each individual entity
        to a dict and returns a list of dicts.

        *Uses _convert_single() for the actual conversion, so
        additions to individual entity conversions should be made
        there or overwritten."""
        output = []
        for entity in entities:
            output.append(self._convert_single(entity))

        return output
