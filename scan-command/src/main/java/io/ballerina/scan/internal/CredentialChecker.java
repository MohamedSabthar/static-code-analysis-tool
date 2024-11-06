package io.ballerina.scan.internal;

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.Qualifier;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.SymbolKind;
import io.ballerina.compiler.api.symbols.VariableSymbol;
import io.ballerina.compiler.syntax.tree.*;
import io.ballerina.projects.Document;
import io.ballerina.scan.ScannerContext;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.ballerina.scan.internal.CoreRule.*;

public class CredentialChecker extends NodeVisitor {
    private static final Pattern PASSWORD_WORDS = Pattern.compile("password|passwd|pwd|passphrase|secret|clientSecret");
    private static final Pattern URL_PREFIX = Pattern.compile("^\\w{1,8}://");
    private static final Pattern NON_EMPTY_URL_CREDENTIAL = Pattern.compile("(?<user>[^\\s:]*+):(?<password>\\S++)");


    private final Document document;
    private final SyntaxTree syntaxTree;
    private final ScannerContext scannerContext;
    private final SemanticModel semanticModel;
    private final HashMap<Integer, FunctionWithCredentialParam> functionWithCredentialParamHashMap;

    CredentialChecker(Document document, ScannerContext scannerContext, SemanticModel semanticModel) {
        this.document = document;
        this.syntaxTree = document.syntaxTree();
        this.scannerContext = scannerContext;
        this.semanticModel = semanticModel;
        this.functionWithCredentialParamHashMap = (HashMap<Integer, FunctionWithCredentialParam>) scannerContext.userData().get("possibleFunctionsWithCredentials");
    }

    public void analyze() {
        this.visit((ModulePartNode) syntaxTree.rootNode());
    }

    public static boolean isPasswordWord(String word) {
        return PASSWORD_WORDS.matcher(word).find();
    }

    @Override
    public void visit(DefaultableParameterNode defaultableParameterNode) {
        if (defaultableParameterNode.paramName().isEmpty()) {
            return;
        }
        if(isPasswordWord(defaultableParameterNode.paramName().get().text())) {
            Node expression  = defaultableParameterNode.expression();
            if (expression instanceof ExpressionNode expressionNode) {
                validateExpressionNode(expressionNode);
            }
        }
        super.visit(defaultableParameterNode);
    }

    @Override
    public void visit(SpecificFieldNode specificFieldNode) {
        visitSpecificFieldNode(specificFieldNode);
        this.visitSyntaxNode(specificFieldNode);
    }

    private void visitSpecificFieldNode(SpecificFieldNode specificFieldNode) {
        if (!isPasswordWord(specificFieldNode.fieldName().toSourceCode().trim())) {
            return;
        }
        if (specificFieldNode.valueExpr().isEmpty()) {
            Optional<Symbol> identifier = semanticModel.symbol(specificFieldNode);
            if (identifier.isEmpty()) {
                return;
            }
            if (identifier.get().kind() == SymbolKind.VARIABLE) {
                VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                    // 6. new({password}) // inline record with shorthand notation

                    scannerContext.getReporter().reportIssue(document, specificFieldNode.location(), NON_CONFIGURABLE_PASSWORD.rule());
                }
            }
            return;
        }
        ExpressionNode valueNode = specificFieldNode.valueExpr().get();
        if (valueNode.kind() == SyntaxKind.STRING_LITERAL) {
            // 5. new({password: password}) // inline record
            System.out.println("plain text password2 found");
            return;
        }
        if (valueNode.kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
            Optional<Symbol> identifier = semanticModel.symbol(valueNode);
            if (identifier.isEmpty()) {
                return;
            }
            if (identifier.get().kind() == SymbolKind.VARIABLE) {
                VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                    scannerContext.getReporter().reportIssue(document, valueNode.location(), NON_CONFIGURABLE_PASSWORD.rule());
                }
            }
        }
    }

    @Override
    public void visit(BasicLiteralNode basicLiteralNode) {
        if (basicLiteralNode.kind() == SyntaxKind.STRING_LITERAL) {
            String stringLiteral = basicLiteralNode.literalToken().text();
            String cleanedLiteral = stringLiteral.substring(1, stringLiteral.length() - 1);
            if (isUrlWithCredentials(cleanedLiteral)) {
                scannerContext.getReporter().reportIssue(document, basicLiteralNode.location(), HARD_CODED_PASSWORD.rule());
            }
        }
        this.visitSyntaxNode(basicLiteralNode);
    }

    @Override
    public void visit(TemplateExpressionNode templateExpressionNode) {
        if (templateExpressionNode.kind() == SyntaxKind.STRING_TEMPLATE_EXPRESSION) {
            NodeList<Node> content = templateExpressionNode.content();
            StringBuilder pattern = new StringBuilder();
            for (var node : content) {
                if (node.kind() == SyntaxKind.TEMPLATE_STRING) {
                    pattern.append(node.toSourceCode());
                    continue;
                } else if (node.kind() == SyntaxKind.INTERPOLATION) {
                    InterpolationNode interpolationNode = (InterpolationNode) node;
                    ExpressionNode expressionNode = interpolationNode.expression();
                    if (expressionNode.kind() == SyntaxKind.STRING_LITERAL) {
                        pattern.append("xyz");
                        continue;
                    }
                    if (expressionNode.kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
                        Optional<Symbol> identifier = semanticModel.symbol(expressionNode);
                        if (identifier.isEmpty()) {
                            continue;
                        }
                        if (identifier.get().kind() == SymbolKind.VARIABLE) {
                            VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                            if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                                pattern.append("xyz");
                                continue;
                            }
                        }
                        continue;
                    }

                }
                pattern.append("xyz");
            }
            if (isUrlWithCredentials(pattern.toString())) {
                scannerContext.getReporter().reportIssue(document, templateExpressionNode.location(), HARD_CODED_PASSWORD.rule());
            }
        }
        super.visit(templateExpressionNode);
    }

    private static boolean isUrlWithCredentials(String stringLiteral) {
        if (URL_PREFIX.matcher(stringLiteral).find()) {
            try {
                String userInfo = new URL(stringLiteral).getUserInfo();
                if (userInfo != null) {
                    Matcher matcher = NON_EMPTY_URL_CREDENTIAL.matcher(userInfo);
                    return matcher.matches();
                }
            } catch (MalformedURLException e) {
                // ignore, stringLiteral is not a valid URL
            }
        }
        return false;
    }

    @Override
    public void visit(VariableDeclarationNode variableDeclarationNode) {
        visitVariableDeclaration(variableDeclarationNode);
        super.visit(variableDeclarationNode);
    }

    private void visitVariableDeclaration(VariableDeclarationNode variableDeclarationNode) {
        if (variableDeclarationNode.initializer().isEmpty()) {
            return;
        }
        BindingPatternNode bindingPattern = variableDeclarationNode.typedBindingPattern().bindingPattern();
        if (!isPasswordWord(bindingPattern.toSourceCode().trim())) {
            return;
        }
        ExpressionNode expressionNode = variableDeclarationNode.initializer().get();
        validateExpressionNode(expressionNode);
    }

    @Override
    public void visit(NamedArgumentNode namedArgumentNode) {
        if (!isPasswordWord(namedArgumentNode.argumentName().name().text().trim())) {
            return;
        }
        if (namedArgumentNode.expression().kind() == SyntaxKind.STRING_LITERAL) {
            // 1. new(password = password) // simple named argument
            scannerContext.getReporter().reportIssue(document, namedArgumentNode.expression().location(), HARD_CODED_PASSWORD.rule());
            return;
        }
        if (namedArgumentNode.expression().kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
            Optional<Symbol> identifier = semanticModel.symbol(namedArgumentNode.expression());
            if (identifier.isEmpty()) {
                return;
            }
            if (identifier.get().kind() == SymbolKind.VARIABLE) {
                VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                    scannerContext.getReporter().reportIssue(document, namedArgumentNode.expression().location(), NON_CONFIGURABLE_PASSWORD.rule());
                }
            }
        }
    }

    @Override
    public void visit(RecordFieldWithDefaultValueNode recordFieldWithDefaultValueNode) {
        if (isPasswordWord(recordFieldWithDefaultValueNode.fieldName().text().trim())) {
            validateExpressionNode(recordFieldWithDefaultValueNode.expression());
        }
        super.visit(recordFieldWithDefaultValueNode);
    }

    @Override
    public void visit(ModuleVariableDeclarationNode moduleVariableDeclarationNode) {
        this.visitVariableDeclaration(moduleVariableDeclarationNode);
        super.visit(moduleVariableDeclarationNode);
    }

    private void visitVariableDeclaration(ModuleVariableDeclarationNode moduleVariableDeclarationNode) {
        if (moduleVariableDeclarationNode.initializer().isEmpty()) {
            return;
        }
        BindingPatternNode bindingPattern = moduleVariableDeclarationNode.typedBindingPattern().bindingPattern();
        if (!isPasswordWord(bindingPattern.toSourceCode().trim())) {
            return;
        }
        ExpressionNode expressionNode = moduleVariableDeclarationNode.initializer().get();
        validateExpressionNode(expressionNode);
    }

    private void validateExpressionNode(ExpressionNode expressionNode) {
        if (expressionNode.kind() == SyntaxKind.STRING_LITERAL) {
            // 1. new(password = password) // simple named argument
            scannerContext.getReporter().reportIssue(document, expressionNode.location(), HARD_CODED_PASSWORD.rule());
            return;
        }

        if (expressionNode.kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
            Optional<Symbol> identifier = semanticModel.symbol(expressionNode);
            if (identifier.isEmpty()) {
                return;
            }
            if (identifier.get().kind() == SymbolKind.VARIABLE) {
                VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                    scannerContext.getReporter().reportIssue(document, expressionNode.location(), NON_CONFIGURABLE_PASSWORD.rule());
                }
            }
        }
    }

    @Override
    public void visit(ObjectFieldNode objectFieldNode) {
        if (!isPasswordWord(objectFieldNode.fieldName().text().trim())) {
            return;
        }
        if (objectFieldNode.expression().isEmpty()) {
            return;
        }
        ExpressionNode expressionNode = objectFieldNode.expression().get();
        validateExpressionNode(expressionNode);
        super.visit(objectFieldNode);
    }

    @Override
    public void visit(FunctionCallExpressionNode functionCallExpressionNode) {
        Optional<Symbol> functionCallExpressionSymbol = semanticModel.symbol(functionCallExpressionNode);
        if (functionCallExpressionSymbol.isEmpty()) {
            return;
        }
        if (!functionWithCredentialParamHashMap.containsKey(functionCallExpressionSymbol.get().hashCode())) {
            return;
        }
        FunctionWithCredentialParam functionWithCredentialParam = functionWithCredentialParamHashMap.get(functionCallExpressionSymbol.get().hashCode());
        List<PositionalArgs> clonedPasswordParams = new ArrayList<>(List.copyOf(functionWithCredentialParam.positionalArgs()));
        int currentPos = 0;
        for (FunctionArgumentNode arg : functionCallExpressionNode.arguments()) {
            if (clonedPasswordParams.isEmpty()) {
                return;
            }

            PositionalArgs currentPasswordParam = clonedPasswordParams.remove(0);
            if (arg.kind() != SyntaxKind.POSITIONAL_ARG) {
                return;
            }
            PositionalArgumentNode positionalArgumentNode = (PositionalArgumentNode) arg;
            if (positionalArgumentNode.expression().kind() == SyntaxKind.STRING_LITERAL && currentPos == currentPasswordParam.position()) {
                scannerContext.getReporter().reportIssue(document, positionalArgumentNode.expression().location(), HARD_CODED_PASSWORD.rule());
            } else if (positionalArgumentNode.expression().kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
                Optional<Symbol> identifier = semanticModel.symbol(positionalArgumentNode.expression());
                if (identifier.isEmpty()) {
                    return;
                }
                if (identifier.get().kind() == SymbolKind.VARIABLE) {
                    VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                    if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                        scannerContext.getReporter().reportIssue(document, positionalArgumentNode.expression().location(), NON_CONFIGURABLE_PASSWORD.rule());
                    }
                }
            }
            currentPos++;
        }
        super.visit(functionCallExpressionNode);
    }

    @Override
    public void visit(MethodCallExpressionNode functionCallExpressionNode) {
        Optional<Symbol> fceNsymbol = semanticModel.symbol(functionCallExpressionNode);
        if (fceNsymbol.isEmpty()) {
            return;
        }
        if (!functionWithCredentialParamHashMap.containsKey(fceNsymbol.get().hashCode())) {
            return;
        }
        FunctionWithCredentialParam functionWithCredentialParam = functionWithCredentialParamHashMap.get(fceNsymbol.get().hashCode());
        List<PositionalArgs> clonedPasswordParams = new ArrayList<>(List.copyOf(functionWithCredentialParam.positionalArgs()));
        int currentPos = 0;
        for (FunctionArgumentNode arg : functionCallExpressionNode.arguments()) {
            if (clonedPasswordParams.isEmpty()) {
                return;
            }

            PositionalArgs currentPasswordParam = clonedPasswordParams.remove(0);
            if (arg.kind() != SyntaxKind.POSITIONAL_ARG) {
                return;
            }
            PositionalArgumentNode positionalArgumentNode = (PositionalArgumentNode) arg;
            if (positionalArgumentNode.expression().kind() == SyntaxKind.STRING_LITERAL && currentPos == currentPasswordParam.position()) {
                scannerContext.getReporter().reportIssue(document, positionalArgumentNode.expression().location(), HARD_CODED_PASSWORD.rule());
            } else if (positionalArgumentNode.expression().kind() == SyntaxKind.SIMPLE_NAME_REFERENCE) {
                Optional<Symbol> identifier = semanticModel.symbol(positionalArgumentNode.expression());
                if (identifier.isEmpty()) {
                    return;
                }
                if (identifier.get().kind() == SymbolKind.VARIABLE) {
                    VariableSymbol variableSymbol = (VariableSymbol) identifier.get();
                    if (variableSymbol.qualifiers().stream().map(qualifier -> qualifier.name().trim()).noneMatch(q -> Qualifier.CONFIGURABLE.name().equals(q))) {
                        scannerContext.getReporter().reportIssue(document, positionalArgumentNode.expression().location(), NON_CONFIGURABLE_PASSWORD.rule());
                    }
                }
            }
            currentPos++;
        }
        super.visit(functionCallExpressionNode);
    }
}

record PositionalArgs(int position, String paramName) {

}


