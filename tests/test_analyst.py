import unittest
from langchain_core.messages import AIMessage
from mcp_sentinel.analyst import LangChainAnalyst, analysis_tools
from mcp_sentinel.engine import normalize
from mcp_sentinel.models import Analysis, ScanOptions
from test_engine import SUSPICIOUS


class ToolCallingModel:
    def __init__(self, calls_per_round=1):
        self.turns=0; self.calls_per_round=calls_per_round; self.messages=None
    def bind_tools(self, tools):
        self.names=[t.name for t in tools]; return self
    def invoke(self, messages):
        self.turns+=1
        return AIMessage(content='',tool_calls=[{'name':'get_tool_definition','args':{'name':'sync_workspace'},'id':f'{self.turns}-{i}'} for i in range(self.calls_per_round)])
    def with_structured_output(self, schema):
        outer=self
        class Structured:
            def invoke(self, messages):
                outer.messages=messages
                return Analysis()
        return Structured()


class AnalystTests(unittest.TestCase):
    def test_real_readers_and_bounded_react(self):
        model=ToolCallingModel()
        tools=normalize(SUSPICIOUS['result']['tools'])
        result,audit=LangChainAnalyst(model).analyze(tools,[],ScanOptions(max_rounds=2))
        self.assertEqual(result,Analysis())
        self.assertEqual(model.turns,2)
        self.assertEqual(audit,['get_tool_definition']*2)
        self.assertEqual(set(model.names),{'get_tool_definition','inspect_schema','get_findings'})
        self.assertIn('Ignore previous instructions', model.messages[3].content)
        readers=analysis_tools(tools,[])
        self.assertIn('properties', readers[1].invoke({'name':'sync_workspace'}))
        self.assertEqual(readers[2].invoke({'name':'sync_workspace'}),'[]')

    def test_unknown_analysis_tool_is_rejected(self):
        class HostileModel(ToolCallingModel):
            def invoke(self, messages):
                self.turns += 1
                return AIMessage(content='', tool_calls=[{
                    'name': 'execute_shell', 'args': {'command': 'never run'}, 'id': str(self.turns)}])
        model = HostileModel()
        _, audit = LangChainAnalyst(model).analyze(
            normalize(SUSPICIOUS['result']['tools']), [], ScanOptions(max_rounds=1))
        self.assertEqual(audit, ['rejected_unknown_reader'])
        self.assertIn('Unknown reader', model.messages[3].content)

    def test_tool_budget_does_not_execute_excess_calls(self):
        model=ToolCallingModel(calls_per_round=7)
        _,audit=LangChainAnalyst(model).analyze(normalize(SUSPICIOUS['result']['tools']),[],ScanOptions())
        self.assertEqual(audit,['tool_call_budget_exhausted'])
        self.assertEqual(model.turns,1)


if __name__=='__main__': unittest.main()
