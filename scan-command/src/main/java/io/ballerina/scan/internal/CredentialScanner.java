package io.ballerina.scan.internal;

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.Qualifier;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.SymbolKind;
import io.ballerina.compiler.api.symbols.VariableSymbol;
import io.ballerina.compiler.syntax.tree.*;
import io.ballerina.projects.Document;
import io.ballerina.scan.ScannerContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

public class CredentialScanner extends NodeVisitor {

    private final Document document;
    private final SyntaxTree syntaxTree;
    private final ScannerContext scannerContext;
    private final SemanticModel semanticModel;

    CredentialScanner(Document document, ScannerContext scannerContext, SemanticModel semanticModel) {
        this.document = document;
        this.syntaxTree = document.syntaxTree();
        this.scannerContext = scannerContext;
        this.semanticModel = semanticModel;
    }

    public void analyze() {
        this.visit((ModulePartNode) syntaxTree.rootNode());
    }

    @Override
    public void visit(MethodDeclarationNode functionDefinitionNode) {
        SeparatedNodeList<ParameterNode> parameters = functionDefinitionNode.methodSignature().parameters();
        List<PositionalArgs> passwordParameters = new ArrayList<>();
        int possition = 0;
        for (var parameter : parameters) {
            String name = "";
            if (parameter.kind() == SyntaxKind.DEFAULTABLE_PARAM) {
                DefaultableParameterNode defaultableParameterNode = (DefaultableParameterNode) parameter;
                if (defaultableParameterNode.paramName().isEmpty()) {
                    possition++;
                    continue;
                }
                name = defaultableParameterNode.paramName().get().text().trim();
            } else if (parameter.kind() == SyntaxKind.REQUIRED_PARAM) {
                RequiredParameterNode requiredParameterNode = (RequiredParameterNode) parameter;
                if (requiredParameterNode.paramName().isEmpty()) {
                    possition++;
                    continue;
                }
                name = requiredParameterNode.paramName().get().text().trim();
            }
            if (name.equals("password")) {
                passwordParameters.add(new PositionalArgs(possition, parameter.toSourceCode().trim()));
            }
            possition++;
        }
        if (!passwordParameters.isEmpty()) {
            Optional<Symbol> functionSymbol = this.semanticModel.symbol(functionDefinitionNode);
            if (functionSymbol.isEmpty()) {
                return;
            }
            HashMap<Integer, FunctionWithCredentialParam> map = (HashMap<Integer, FunctionWithCredentialParam>) scannerContext.userData().get("possibleFunctionsWithCredentials");
            map.put(functionSymbol.get().hashCode(), new FunctionWithCredentialParam(functionSymbol.get(), passwordParameters));
        }
        super.visit(functionDefinitionNode);
    }

    @Override
    public void visit(FunctionDefinitionNode functionDefinitionNode) {
        SeparatedNodeList<ParameterNode> parameters = functionDefinitionNode.functionSignature().parameters();
        List<PositionalArgs> passwordParameters = new ArrayList<>();
        int possition = 0;
        for (var parameter : parameters) {
            String name = "";
            if (parameter.kind() == SyntaxKind.DEFAULTABLE_PARAM) {
                DefaultableParameterNode defaultableParameterNode = (DefaultableParameterNode) parameter;
                if (defaultableParameterNode.paramName().isEmpty()) {
                    possition++;
                    continue;
                }
                name = defaultableParameterNode.paramName().get().text().trim();
            } else if (parameter.kind() == SyntaxKind.REQUIRED_PARAM) {
                RequiredParameterNode requiredParameterNode = (RequiredParameterNode) parameter;
                if (requiredParameterNode.paramName().isEmpty()) {
                    possition++;
                    continue;
                }
                name = requiredParameterNode.paramName().get().text().trim();
            }
            if (CredentialChecker.isPasswordWord(name)) {
                passwordParameters.add(new PositionalArgs(possition, parameter.toSourceCode().trim()));
            }
            possition++;
        }
        if (!passwordParameters.isEmpty()) {
            Optional<Symbol> functionSymbol = this.semanticModel.symbol(functionDefinitionNode);
            if (functionSymbol.isEmpty()) {
                return;
            }
            HashMap<Integer, FunctionWithCredentialParam> map = (HashMap<Integer, FunctionWithCredentialParam>) scannerContext.userData().get("possibleFunctionsWithCredentials");
            map.put(functionSymbol.get().hashCode(), new FunctionWithCredentialParam(functionSymbol.get(), passwordParameters));
        }
        super.visit(functionDefinitionNode);
    }
}


