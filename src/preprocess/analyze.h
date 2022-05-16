
class Analyzer {
public:

public:
  virtual Analyzer() {

  }

  virtual ~Analyzer() {}
}

class AsmAnalyzer : Analyzer {


public:
  AsmAnalyzer() {}
  ~AsmAnalyzer() {}
}

class AstAnalyzer : Analyzer {

public:
  AstAnalyzer() {}
  ~AstAnalyzer() {}
}