/*
 *  Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.ballerina.scan.internal;

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.Qualifier;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.SymbolKind;
import io.ballerina.compiler.api.symbols.VariableSymbol;
import io.ballerina.compiler.syntax.tree.*;
import io.ballerina.projects.Document;
import io.ballerina.scan.ScannerContext;

import java.util.HashMap;
import java.util.Optional;

/**
 * {@code StaticCodeAnalyzer} contains the logic to perform core static code analysis on Ballerina documents.
 *
 * @since 0.1.0
 */
class StaticCodeAnalyzer extends NodeVisitor {
    private final Document document;
    private final SyntaxTree syntaxTree;
    private final ScannerContext scannerContext;
    private final SemanticModel semanticModel;
    private final HashMap<Integer, Symbol> restSymbols = new HashMap<>();

    StaticCodeAnalyzer(Document document, ScannerContextImpl scannerContext, SemanticModel semanticModel) {
        this.document = document;
        this.syntaxTree = document.syntaxTree();
        this.scannerContext = scannerContext;
        this.semanticModel = semanticModel;
    }

    void analyze() {
        this.visit((ModulePartNode) syntaxTree.rootNode());
        RecordAssignmentVisitor rav = new RecordAssignmentVisitor(restSymbols, semanticModel, this.syntaxTree);
        rav.analyze();
    }

    /**
     * Visits check expressions in a Ballerina document and perform static code analysis.
     *
     * @param checkExpressionNode node that represents a check expression
     */
    @Override
    public void visit(CheckExpressionNode checkExpressionNode) {
        if (checkExpressionNode.checkKeyword().kind().equals(SyntaxKind.CHECKPANIC_KEYWORD)) {
            reportIssue(checkExpressionNode, CoreRule.AVOID_CHECKPANIC);
        }
        this.visitSyntaxNode(checkExpressionNode);
    }

    @Override
    public void visit(FunctionDefinitionNode functionDefinitionNode) {
        checkUnusedFunctionParameters(functionDefinitionNode.functionSignature());
        this.visitSyntaxNode(functionDefinitionNode);
    }

    @Override
    public void visit(ExplicitAnonymousFunctionExpressionNode explicitAnonymousFunctionExpressionNode) {
        checkUnusedFunctionParameters(explicitAnonymousFunctionExpressionNode.functionSignature());
        this.visitSyntaxNode(explicitAnonymousFunctionExpressionNode);
    }

    @Override
    public void visit(ImplicitAnonymousFunctionExpressionNode implicitAnonymousFunctionExpressionNode) {
        Node params = implicitAnonymousFunctionExpressionNode.params();
        if (params instanceof ImplicitAnonymousFunctionParameters parameters) {
            parameters.parameters().forEach(parameter -> {
                reportIssueIfNodeIsUnused(parameter, CoreRule.UNUSED_FUNCTION_PARAMETER);
            });
            this.visitSyntaxNode(implicitAnonymousFunctionExpressionNode);
            return;
        }
        if (params instanceof SimpleNameReferenceNode) {
            reportIssueIfNodeIsUnused(params, CoreRule.UNUSED_FUNCTION_PARAMETER);
        }
        this.visitSyntaxNode(implicitAnonymousFunctionExpressionNode);
    }

//    @Override
//    public void visit(ExplicitNewExpressionNode explicitNewExpressionNode) {
//        var argList = explicitNewExpressionNode.parenthesizedArgList();
//    }

    @Override
    public void visit(ImplicitNewExpressionNode implicitNewExpressionNode) {
        if (implicitNewExpressionNode.parenthesizedArgList().isEmpty()) {
            return;
        }
        ParenthesizedArgList parenthesizedArgList = implicitNewExpressionNode.parenthesizedArgList().get();
        if (parenthesizedArgList.arguments().isEmpty()) {
            return;
        }
        for (FunctionArgumentNode argumentNode : parenthesizedArgList.arguments()) {
            if (argumentNode.kind() == SyntaxKind.NAMED_ARG) {
                NamedArgumentNode namedArgumentNode = (NamedArgumentNode) argumentNode;
                if (!(namedArgumentNode.argumentName().name().text().trim().equals("password"))) {
                    continue;
                }
                if (namedArgumentNode.expression().kind() == SyntaxKind.STRING_LITERAL) {
                    // 1. new(password = password) // simple named argument
                    System.out.println("plain text password");
                    continue;
                }
                if (namedArgumentNode.expression().kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
                    Optional<Symbol> identifier = semanticModel.symbol(namedArgumentNode.expression());
                    if (identifier.isEmpty()) {
                        continue;
                    }
                    if (identifier.get().kind() == SymbolKind.VARIABLE) {
                        VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                        if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                            System.out.println("Not a configurable");
                        }
                    }
                }
            } else if (argumentNode.kind() == SyntaxKind.POSITIONAL_ARG) {
                PositionalArgumentNode positionalArgumentNode = (PositionalArgumentNode) argumentNode;
                ExpressionNode expression = positionalArgumentNode.expression();
                if (expression.kind() == SyntaxKind.MAPPING_CONSTRUCTOR) {
                    MappingConstructorExpressionNode mappingConstructorExpressionNode = (MappingConstructorExpressionNode) expression;
                    for (MappingFieldNode field: mappingConstructorExpressionNode.fields()) {
                        if (field.kind() != SyntaxKind.SPECIFIC_FIELD) {
                            continue;
                        }
                        SpecificFieldNode specificFieldNode = (SpecificFieldNode) field;
                        if (!specificFieldNode.fieldName().toSourceCode().trim().equals("password")) {
                            continue;
                        }
                        if(specificFieldNode.valueExpr().isEmpty()) {

                            Optional<Symbol> identifier = semanticModel.symbol(specificFieldNode);
                            if (identifier.isEmpty()) {
                                continue;
                            }
                            if (identifier.get().kind() == SymbolKind.VARIABLE) {
                                VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                                if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                                    // 6. new({password}) // inline record with shorthand notation
                                    System.out.println("Not a configurable3");
                                }
                            }
                            continue;
                        }
                        ExpressionNode valueNode = specificFieldNode.valueExpr().get();
                        if (valueNode.kind() == SyntaxKind.STRING_LITERAL) {
                            // 5. new({password: password}) // inline record
                            System.out.println("plain text password2");
                            continue;
                        }
                        if (valueNode.kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
                            Optional<Symbol> identifier = semanticModel.symbol(valueNode);
                            if (identifier.isEmpty()) {
                                continue;
                            }
                            if (identifier.get().kind() == SymbolKind.VARIABLE) {
                                VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                                if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                                    System.out.println("Not a configurable2");
                                }
                            }
                        }
                    }
                }
                System.out.println(expression);
            } else if (argumentNode.kind() == SyntaxKind.REST_ARG) {
                RestArgumentNode restArgumentNode = (RestArgumentNode) argumentNode;
                ExpressionNode expression = restArgumentNode.expression();
                if (expression.kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
                    Optional<Symbol> identifier = semanticModel.symbol(expression);
                    if (identifier.isEmpty()) {
                        continue;
                    }
                    Symbol restSymbol = identifier.get();
                    this.restSymbols.put(restSymbol.hashCode(), restSymbol);
                    // todo: get the record value from the identifier and loop and verify
                }
            }
        }
    }

    private void checkUnusedFunctionParameters(FunctionSignatureNode functionSignatureNode) {
        functionSignatureNode.parameters().forEach(parameter -> {
            if (parameter instanceof IncludedRecordParameterNode includedRecordParameterNode) {
                includedRecordParameterNode.paramName().ifPresent(name -> {
                    reportIssueIfNodeIsUnused(name, CoreRule.UNUSED_FUNCTION_PARAMETER);
                });
            } else {
                reportIssueIfNodeIsUnused(parameter, CoreRule.UNUSED_FUNCTION_PARAMETER);
            }
            this.visitSyntaxNode(parameter);
        });
    }

    private void reportIssueIfNodeIsUnused(Node node, CoreRule coreRule) {
        if (isUnusedNode(node)) {
            reportIssue(node, coreRule);
        }
    }

    private void reportIssue(Node node, CoreRule coreRule) {
        scannerContext.getReporter().reportIssue(document, node.location(), coreRule.rule());
    }

    private boolean isUnusedNode(Node node) {
        Optional<Symbol> symbol = semanticModel.symbol(node);
        return symbol.filter(value -> semanticModel.references(value).size() == 1).isPresent();
    }
}

class RecordAssignmentVisitor extends NodeVisitor {
    private final HashMap<Integer, Symbol> restSymbols;
    private final SemanticModel semanticModel;
    private final SyntaxTree syntaxTree;

    RecordAssignmentVisitor(HashMap<Integer, Symbol> restSymbols, SemanticModel semanticModel, SyntaxTree syntaxTree) {
        this.restSymbols = restSymbols;
        this.semanticModel = semanticModel;
        this.syntaxTree = syntaxTree;
    }

    public void analyze() {
        this.visit((ModulePartNode) syntaxTree.rootNode());
    }

    @Override
    public void visit(AssignmentStatementNode assignmentStatementNode) {
        assignmentStatementNode.expression();
    }
}
