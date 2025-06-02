import unittest
import time
import binascii
from utils.insert_data_action import InsertDataAction

class TestInsertDataAction(unittest.TestCase):

    def test_no_rules(self):
        action = InsertDataAction([], time.time())
        self.assertIsNone(action.get_data_to_insert({"action": "test"}, time.time()))

    def test_no_matching_action(self):
        rules = [{
            "action": "my_action", "data": "test_data", "data_type": "bytes", 
            "position": "before", "delay_sec": 0
        }]
        action = InsertDataAction(rules, time.time())
        self.assertIsNone(action.get_data_to_insert({"action": "other_action"}, time.time()))

    def test_bytes_insertion_before(self):
        data_str = "Hello"
        rules = [{
            "action": "insert_hello", "data": data_str, "data_type": "bytes",
            "position": "before", "delay_sec": 0
        }]
        start_time = time.time()
        action = InsertDataAction(rules, start_time)
        
        # Simulate current time for the check
        current_eval_time = start_time 
        
        expected_data = data_str.encode('utf-8')
        result = action.get_data_to_insert({"action": "insert_hello"}, current_eval_time)
        
        self.assertIsNotNone(result)
        if result:
            result_data, result_pos = result
            self.assertEqual(result_data, expected_data)
            self.assertEqual(result_pos, "before")

    def test_hex_insertion_after(self):
        hex_str = "aabbcc"
        rules = [{
            "action": "insert_hex", "data": hex_str, "data_type": "hex",
            "position": "after", "delay_sec": 0
        }]
        start_time = time.time()
        action = InsertDataAction(rules, start_time)
        
        # Simulate current time for the check
        current_eval_time = start_time

        expected_data = binascii.unhexlify(hex_str)
        result = action.get_data_to_insert({"action": "insert_hex"}, current_eval_time)
        
        self.assertIsNotNone(result)
        if result:
            result_data, result_pos = result
            self.assertEqual(result_data, expected_data)
            self.assertEqual(result_pos, "after")

    def test_time_delay_not_met(self):
        rules = [{
            "action": "delayed_action", "data": "data", "data_type": "bytes",
            "position": "before", "delay_sec": 5 # 5 seconds delay
        }]
        # Proxy started very recently
        very_recent_start_time = time.time() - 0.1 
        action = InsertDataAction(rules, very_recent_start_time)
        
        # Try to get data almost immediately (current_time is close to very_recent_start_time)
        self.assertIsNone(action.get_data_to_insert({"action": "delayed_action"}, very_recent_start_time + 1))

    def test_time_delay_met(self):
        rules = [{
            "action": "delayed_action", "data": "data", "data_type": "bytes",
            "position": "before", "delay_sec": 1 # 1 second delay
        }]
        # Proxy started 2 seconds ago
        start_time_2_sec_ago = time.time() - 2 
        action = InsertDataAction(rules, start_time_2_sec_ago)
        
        # Try to get data now (current_time is time.time(), which is 2s after start_time_2_sec_ago)
        current_eval_time = time.time()
        result = action.get_data_to_insert({"action": "delayed_action"}, current_eval_time)
        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result[0], b"data")

    def test_invalid_data_type(self):
        rules = [{
            "action": "bad_type", "data": "data", "data_type": "invalid",
            "position": "before", "delay_sec": 0
        }]
        action = InsertDataAction(rules, time.time())
        self.assertIsNone(action.get_data_to_insert({"action": "bad_type"}, time.time()))

    def test_invalid_hex_data(self):
        rules = [{
            "action": "bad_hex", "data": "xxzzgg", "data_type": "hex", # Invalid hex
            "position": "before", "delay_sec": 0
        }]
        action = InsertDataAction(rules, time.time())
        self.assertIsNone(action.get_data_to_insert({"action": "bad_hex"}, time.time()))
        
    def test_default_position_and_delay(self):
        data_str = "default_data"
        rules = [{
            "action": "default_test", "data": data_str, "data_type": "bytes"
            # No position, no delay_sec specified, should default
        }]
        start_time = time.time()
        action = InsertDataAction(rules, start_time)
        
        current_eval_time = start_time # delay_sec defaults to 0
        
        expected_data = data_str.encode('utf-8')
        result = action.get_data_to_insert({"action": "default_test"}, current_eval_time)
        
        self.assertIsNotNone(result)
        if result:
            result_data, result_pos = result
            self.assertEqual(result_data, expected_data)
            self.assertEqual(result_pos, "before") # Default position

    def test_malformed_rule_no_data_field(self):
        # Rule is missing the 'data' field entirely
        rules = [{"action": "no_data_action", "data_type": "bytes", "delay_sec": 0}] 
        action = InsertDataAction(rules, time.time())
        self.assertIsNone(action.get_data_to_insert({"action": "no_data_action"}, time.time()))

    def test_empty_data_string_in_rule(self):
        # Rule has 'data' field, but it's an empty string
        rules = [{"action": "empty_data_action", "data": "", "data_type": "bytes", "delay_sec": 0}]
        action = InsertDataAction(rules, time.time())
        # Current behavior: if data_str is empty, it skips. This might be desired.
        # If an empty byte string b'' is a valid insertion, InsertDataAction would need adjustment.
        # For now, testing existing behavior.
        self.assertIsNone(action.get_data_to_insert({"action": "empty_data_action"}, time.time()))


    def test_malformed_rule_no_action_in_rule_definition(self):
        # Rule definition itself is missing the 'action' key.
        rules = [{"data": "some_data", "data_type": "bytes", "delay_sec": 0}] 
        action = InsertDataAction(rules, time.time())
        # The .get_data_to_insert method iterates through self.rules.
        # If a rule in self.rules doesn't have an 'action' key, rule.get('action') will be None.
        # This won't match any message_action unless message_action is also None (which it shouldn't be).
        self.assertIsNone(action.get_data_to_insert({"action": "any_message_action"}, time.time()))

if __name__ == '__main__':
    unittest.main()
