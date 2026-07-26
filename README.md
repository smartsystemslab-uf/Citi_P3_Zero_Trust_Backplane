# Zero Trust Backplane 

By September 14, the goal is to deliver a working Zero Trust Backplane prototype that can analyze Citi’s existing banking-agent system, identify required protection points, generate PEP nodes and policies, enforce runtime authorization, and safely handle PDP delay, cached decisions, permit expiration, request replay, policy updates, and identity revocation.
The prototype should demonstrate three main capabilities:
1.	It can analyze Citi’s existing banking-agent architecture.
2.	It can automatically identify and generate the required Zero Trust protection nodes.
3.	It can block unauthorized operations and safely handle PDP delay, cached decisions, expiration, and revocation.

## Developer Guidelines:
1. For every script you add here, please make sure you have ensure there is 100% unit test coverage. It's no need to post your unit test code here, but in the future, if our project is large enough as an industry-level project, unit test code is required to be committed to the repository. 
Learn more about unit test here: https://www.ibm.com/think/topics/unit-testing.

2. Every `.py` file or other executable file added to this project must also have corresponding integration tests codes included in the repository. All integration tests must pass before submission. 
Learn more about integration test here: https://circleci.com/blog/unit-testing-vs-integration-testing/

3. The use of AI tools and other unit testing tools is encouraged. Please use whichever tools work best for your workflow.

4. When pushing changes to the repository, please include a brief description of what was changed and why the change was necessary.
