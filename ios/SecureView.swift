import UIKit
import React

@objc(SecureView)
class SecureView: UIView {
  public var isSecure: Bool {
      get { textField.isSecureTextEntry }
      set { textField.isSecureTextEntry = newValue }
  }
  
  private var secureView: UIView
  
  private var textField: UITextField = {
      let view = UITextField()
      view.isSecureTextEntry = true
      return view
  }()
  
  public override init(frame: CGRect) {
      guard let secureView = textField.layer.sublayers?.first?.delegate as? UIView else {
          preconditionFailure("Invalid hierarchy")
      }
      self.secureView = secureView
      super.init(frame: frame)
      setupView()
  }
  
  public required init?(coder: NSCoder) {
      guard let secureView = textField.layer.sublayers?.first?.delegate as? UIView else {
          preconditionFailure("Invalid hierarchy")
      }
      self.secureView = secureView
      super.init(coder: coder)
      setupView()
  }
  
  func addReactSubview(_ subview: UIView!) {
    super.addSubview(subview)
  }

  override func layoutSubviews() {
    super.layoutSubviews()
    for subview in subviews {
      subview.frame = self.bounds
    }
  }
  
  open override var subviews: [UIView] {
      secureView.subviews + super.subviews
  }
  
  open override func insertSubview(_ view: UIView, at index: Int) {
      secureView.insertSubview(view, at: index)
  }
  
  open override func exchangeSubview(at index1: Int, withSubviewAt index2: Int) {
      secureView.exchangeSubview(at: index1, withSubviewAt: index2)
  }

  public override func addSubview(_ view: UIView) {
      secureView.addSubview(view)
  }
  
  open override func insertSubview(_ view: UIView, belowSubview siblingSubview: UIView) {
      secureView.insertSubview(view, belowSubview: siblingSubview)
  }
  
  open override func insertSubview(_ view: UIView, aboveSubview siblingSubview: UIView) {
      secureView.insertSubview(view, aboveSubview: siblingSubview)
  }
  
  open override func bringSubviewToFront(_ view: UIView) {
      secureView.bringSubviewToFront(view)
  }
  
  open override func sendSubviewToBack(_ view: UIView) {
      secureView.sendSubviewToBack(view)
  }
  
  open override func didAddSubview(_ subview: UIView) {
      secureView.didAddSubview(subview)
  }
  
  open override func willRemoveSubview(_ subview: UIView) {
      secureView.willRemoveSubview(subview)
  }
  
  open override func viewWithTag(_ tag: Int) -> UIView? {
      secureView.viewWithTag(tag)
  }
  
  open override var constraints: [NSLayoutConstraint] {
      secureView.constraints
  }
  
  open override func addConstraint(_ constraint: NSLayoutConstraint) {
      secureView.addConstraint(constraint)
  }
  
  open override func addConstraints(_ constraints: [NSLayoutConstraint]) {
      secureView.addConstraints(constraints)
  }
  
  open override func removeConstraint(_ constraint: NSLayoutConstraint) {
      secureView.removeConstraint(constraint)
  }
  
  open override func removeConstraints(_ constraints: [NSLayoutConstraint]) {
      secureView.removeConstraints(constraints)
  }
  
  private func setupView() {
    secureView.isUserInteractionEnabled = true
    secureView.subviews.forEach { $0.removeFromSuperview() }
    secureView.translatesAutoresizingMaskIntoConstraints = false
    super.addSubview(secureView)

    NSLayoutConstraint.activate([
        secureView.topAnchor.constraint(equalTo: topAnchor),
        secureView.bottomAnchor.constraint(equalTo: bottomAnchor),
        secureView.leadingAnchor.constraint(equalTo: leadingAnchor),
        secureView.trailingAnchor.constraint(equalTo: trailingAnchor)
    ])
  }
}
